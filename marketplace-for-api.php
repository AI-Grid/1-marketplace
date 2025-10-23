
<?php
/*
Plugin Name: OpenSim Marketplace (API Delivery)
Description: Marketplace for OpenSim prims with external delivery API integration, orders, redelivery, and logs. Includes front-end buy page, advanced ignore filters, ignore rules by UUID or Name (exact/contains), user balance display, bulk-trash for ignored items, editor UI, and dark mode UI.
Version: 2.0
Author: Tasia
Requires PHP: 8.0
*/

if (!defined('ABSPATH')) exit;

// ---- Cron Schedule ----
add_filter('cron_schedules', function($schedules) {
    $schedules['five_minutes'] = [
        'interval' => 300,
        'display'  => 'Every 5 Minutes'
    ];
    return $schedules;
});

class OpenSimMarketplace {
    private ?mysqli $os_db = null;
    private ?mysqli $money_db = null;
    private string $delivery_api_url = '';
    private string $delivery_api_password = '';
    private array $region_uuids = [];
    private array $region_labels = [];
    private array $region_delivery_urls = [];
    private string $region_uuid = '';
    private array $ignore_list = [];
    private string $plugin_version = '2.0';
    private ?array $avatar_session = null;
    private ?array $cached_buyer_context = null;
    private string $avatar_cookie_name = 'osmp_avatar_session';
    private int $avatar_cookie_lifetime = 604800; // 7 days
    private string $texture_proxy_template = '';

    public function __construct() {
        add_action('init', [$this, 'register_cpt']);
        add_action('init', [$this, 'register_shortcodes']);
        add_action('admin_menu', [$this, 'admin_menu']);
        add_action('wp_ajax_osmp_purchase', [$this, 'handle_purchase']);
        add_action('wp_ajax_nopriv_osmp_purchase', [$this, 'handle_purchase']);
        add_action('wp_ajax_osmp_avatar_login', [$this, 'handle_avatar_login']);
        add_action('wp_ajax_nopriv_osmp_avatar_login', [$this, 'handle_avatar_login']);
        add_action('wp_ajax_osmp_avatar_logout', [$this, 'handle_avatar_logout']);
        add_action('wp_ajax_nopriv_osmp_avatar_logout', [$this, 'handle_avatar_logout']);
        add_action('osmp_cron_import', [$this, 'sync_prims']);
        add_action('rest_api_init', [$this, 'register_rest_api']);

        // Editor meta boxes for opensim_item
        add_action('add_meta_boxes', [$this, 'register_item_metaboxes']);
        add_action('save_post_opensim_item', [$this, 'save_item_meta']);
        // Admin list columns
        add_filter('manage_opensim_item_posts_columns', [$this, 'add_admin_columns']);
        add_action('manage_opensim_item_posts_custom_column', [$this, 'render_admin_columns'], 10, 2);
        add_filter('manage_edit-opensim_item_sortable_columns', [$this, 'sortable_admin_columns']);
        add_action('pre_get_posts', [$this, 'handle_sorting']);

        register_activation_hook(__FILE__, [$this, 'activate']);
        register_deactivation_hook(__FILE__, ['OpenSimMarketplace', 'deactivate']);

        $this->setup_cron();

        // Defer config + DB connections until pluggable functions exist
        add_action('plugins_loaded', function () {
            $this->init_config();
            $this->init_database_connections();
            $this->load_avatar_session();
        });
    }

    // ---- Activation ----
    public function activate(): void {
        $this->create_tables();
        $this->maybe_create_market_page();
    }

    private function maybe_create_market_page(): void {
        $existing_id = (int) get_option('osmp_market_page_id', 0);
        if ($existing_id && get_post_status($existing_id)) return;

        $page_id = wp_insert_post([
            'post_title'   => 'Marketplace',
            'post_content' => '[osmp_market]',
            'post_status'  => 'publish',
            'post_type'    => 'page',
        ]);
        if ($page_id && !is_wp_error($page_id)) {
            update_option('osmp_market_page_id', (int)$page_id);
        }
    }

    // ---- Initialization ----
    private function init_config(): void {
        $default_api = 'http://i.let-us.cyou:2023/send';
        $this->delivery_api_url = rtrim((string) get_option('osmp_delivery_api_url', $default_api), "/\t\n\r ");
        if ($this->delivery_api_url === '') {
            $this->delivery_api_url = $default_api;
        }

        $this->delivery_api_password = $this->decrypt_option('osmp_delivery_api_password', '');

        $this->region_labels = [];
        $this->region_delivery_urls = [];
        $raw_regions = get_option('osmp_region_uuids', '');
        if (is_array($raw_regions)) {
            $raw_list = $raw_regions;
        } else {
            $raw_list = preg_split('/[\r\n,]+/', (string) $raw_regions) ?: [];
        }

        $valid_regions = [];
        foreach ($raw_list as $value) {
            $value = trim((string) $value);
            if ($value === '') {
                continue;
            }

            $parts = array_map('trim', explode('|', $value));
            $uuid_part  = $parts[0] ?? '';
            $label_part = $parts[1] ?? '';
            $api_part   = $parts[2] ?? '';

            if ($this->is_valid_uuid($uuid_part)) {
                $normalized = strtolower($uuid_part);
                if (!isset($this->region_labels[$normalized])) {
                    $valid_regions[] = $uuid_part;
                    $this->region_labels[$normalized] = $label_part !== '' ? $label_part : $uuid_part;
                }

                if ($api_part !== '') {
                    $api_url = rtrim((string) $api_part, "/\t\n\r ");
                    if ($api_url !== '' && filter_var($api_url, FILTER_VALIDATE_URL)) {
                        $this->region_delivery_urls[$normalized] = $api_url;
                    }
                }
            }
        }

        if (empty($valid_regions)) {
            $fallback_region = (string) get_option('osmp_region_uuid', '');
            if ($this->is_valid_uuid($fallback_region)) {
                $valid_regions[] = $fallback_region;
                $this->region_labels[strtolower($fallback_region)] = $fallback_region;
            }
        }

        $this->region_uuids = array_values($valid_regions);
        $this->region_uuid  = $this->region_uuids[0] ?? (string) get_option('osmp_region_uuid', '');
        if ($this->region_uuid !== '' && !$this->is_valid_uuid($this->region_uuid)) {
            $this->region_uuid = '';
        }

        $this->ignore_list = get_option('osmp_ignore_list', []); // legacy option only
        $this->texture_proxy_template = trim((string) get_option('osmp_texture_proxy_template', ''));
    }

    private function get_region_delivery_api_url(?string $region_uuid): string {
        $base = $this->delivery_api_url;

        if ($region_uuid) {
            $normalized = strtolower(trim($region_uuid));
            if ($normalized !== '' && isset($this->region_delivery_urls[$normalized]) && $this->region_delivery_urls[$normalized] !== '') {
                $base = $this->region_delivery_urls[$normalized];
            }
        }

        /**
         * Filters the delivery API base URL before a delivery request is dispatched.
         *
         * @param string      $base_url    The resolved base URL.
         * @param string|null $region_uuid The region UUID associated with the order (if any).
         */
        return (string) apply_filters('osmp_delivery_api_base_url', $base, $region_uuid);
    }

    private function init_database_connections(): void {
        try {
            $os_host = get_option('osmp_os_db_host', 'i.let-us.cyou');
            $os_user = get_option('osmp_os_db_user', 'root');
            $os_pass = $this->decrypt_option('osmp_os_db_pass', 'aigrid123');
            $os_name = get_option('osmp_os_db_name', 'opensim');

            $money_host = get_option('osmp_money_db_host', 'i.let-us.cyou');
            $money_user = get_option('osmp_money_db_user', 'root');
            $money_pass = $this->decrypt_option('osmp_money_db_pass', 'aigrid123');
            $money_name = get_option('osmp_money_db_name', 'money');

            if (empty($os_host) || empty($os_user) || empty($money_host) || empty($money_user)) {
                add_action('admin_notices', function() {
                    echo '<div class="notice notice-error"><p>OpenSim Marketplace: Database credentials not configured. Please configure in Settings.</p></div>';
                });
                return;
            }

            $this->os_db = @new mysqli($os_host, $os_user, $os_pass, $os_name);
            if ($this->os_db->connect_error) { error_log("OpenSim DB connection failed: " . $this->os_db->connect_error); $this->os_db = null; }
            else { $this->os_db->set_charset('utf8mb4'); }

            $this->money_db = @new mysqli($money_host, $money_user, $money_pass, $money_name);
            if ($this->money_db->connect_error) { error_log("Money DB connection failed: " . $this->money_db->connect_error); $this->money_db = null; }
            else { $this->money_db->set_charset('utf8mb4'); }
        } catch (Throwable $e) {
            error_log("Database connection error: " . $e->getMessage());
        }
    }

    private function load_avatar_session(): void {
        $this->avatar_session = null;
        $this->cached_buyer_context = null;

        if (empty($_COOKIE[$this->avatar_cookie_name])) {
            return;
        }

        $raw = (string) $_COOKIE[$this->avatar_cookie_name];
        $parts = explode('|', $raw);
        if (count($parts) !== 3) {
            $this->clear_avatar_session();
            return;
        }

        [$uuid, $expires, $signature] = $parts;
        $uuid = trim((string) $uuid);
        $expires = (int) $expires;
        $signature = trim((string) $signature);

        if (!$this->is_valid_uuid($uuid) || $expires <= time()) {
            $this->clear_avatar_session();
            return;
        }

        $expected = $this->build_avatar_cookie_signature($uuid, $expires);
        if (!hash_equals($expected, $signature)) {
            $this->clear_avatar_session();
            return;
        }

        $this->avatar_session = [
            'uuid'    => $uuid,
            'expires' => $expires,
        ];
    }

    private function build_avatar_cookie_signature(string $uuid, int $expires): string {
        return hash_hmac('sha256', $uuid . '|' . $expires, wp_salt('auth'));
    }

    private function write_avatar_cookie(string $value, int $expires): void {
        $args = [
            'expires'  => $expires,
            'path'     => defined('COOKIEPATH') ? (string) COOKIEPATH : '/',
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ];

        if (defined('COOKIE_DOMAIN') && COOKIE_DOMAIN !== '') {
            $args['domain'] = COOKIE_DOMAIN;
        }

        setcookie($this->avatar_cookie_name, $value, $args);

        if (defined('SITECOOKIEPATH') && SITECOOKIEPATH !== $args['path']) {
            $args['path'] = SITECOOKIEPATH;
            setcookie($this->avatar_cookie_name, $value, $args);
        }
    }

    private function issue_avatar_session(string $uuid): void {
        $expires = time() + $this->avatar_cookie_lifetime;
        $payload = implode('|', [
            $uuid,
            (string) $expires,
            $this->build_avatar_cookie_signature($uuid, $expires),
        ]);

        $this->write_avatar_cookie($payload, $expires);

        $this->avatar_session = [
            'uuid'    => $uuid,
            'expires' => $expires,
        ];
        $this->cached_buyer_context = null;
    }

    private function clear_avatar_session(): void {
        $this->avatar_session = null;
        $this->cached_buyer_context = null;
        $this->write_avatar_cookie('', time() - 3600);
    }

    private function get_texture_proxy_url(string $uuid): ?string {
        if (!$this->is_valid_uuid($uuid)) {
            return null;
        }

        $template = trim((string) $this->texture_proxy_template);
        if ($template === '') {
            return null;
        }

        if (strpos($template, '{uuid}') !== false) {
            return str_replace('{uuid}', $uuid, $template);
        }

        $base = rtrim($template, '/');
        return $base . '/' . $uuid;
    }

    private function resolve_buyer_context(bool $with_balance = false): ?array {
        if ($this->cached_buyer_context === null) {
            $context = null;

            if (is_user_logged_in()) {
                $user = wp_get_current_user();
                if ($user && $user->exists()) {
                    $uuid = $this->get_user_avatar_uuid((int) $user->ID);
                    if ($uuid !== '' && $this->is_valid_uuid($uuid)) {
                        $wp_name = trim((string) $user->display_name);
                        if ($wp_name === '') {
                            $wp_name = trim((string) $user->user_login);
                        }

                        $context = [
                            'uuid'    => $uuid,
                            'source'  => 'wp',
                            'wp_name' => $wp_name,
                        ];
                    }
                }
            }

            if ((!$context || empty($context['uuid'])) && $this->avatar_session) {
                $uuid = $this->avatar_session['uuid'] ?? '';
                if ($this->is_valid_uuid($uuid)) {
                    $context = [
                        'uuid'   => $uuid,
                        'source' => 'avatar',
                    ];
                }
            }

            if ($context) {
                $avatar_name = $this->get_avatar_name($context['uuid']);
                $context['avatar_name'] = $avatar_name ?: null;

                if ($context['source'] === 'wp') {
                    $label = $context['wp_name'] ?? '';
                    if ($label === '') {
                        $label = $avatar_name ?: $context['uuid'];
                    } elseif ($avatar_name) {
                        $label .= ' (' . $avatar_name . ')';
                    }
                    $context['display'] = $label;
                } else {
                    $context['display'] = $avatar_name ?: $context['uuid'];
                }
            }

            $this->cached_buyer_context = $context;
        }

        $context = $this->cached_buyer_context;

        if ($with_balance && $context && !array_key_exists('balance', $context)) {
            $context['balance'] = $this->get_user_balance($context['uuid']);
            $this->cached_buyer_context = $context;
        }

        return $context;
    }

    private function setup_cron(): void {
        if (!wp_next_scheduled('osmp_cron_import')) {
            wp_schedule_event(time(), 'five_minutes', 'osmp_cron_import');
        }
    }

    // ---- Security Helpers ----
    private function get_crypto_key(): string {
        if (function_exists('wp_salt')) return wp_salt('secure_auth');
        if (defined('SECURE_AUTH_KEY') && SECURE_AUTH_KEY) return SECURE_AUTH_KEY;
        if (defined('AUTH_KEY') && AUTH_KEY) return AUTH_KEY;
        return hash('sha256', ABSPATH . __FILE__); // fallback
    }

    private function encrypt_option(string $value): string {
        $value = (string)$value;
        if ($value === '') return '';
        $key = $this->get_crypto_key();
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($value, 'AES-256-CBC', $key, 0, $iv);
        return base64_encode($iv . $encrypted);
    }

    private function decrypt_option(string $option_name, string $default = ''): string {
        $encrypted_value = get_option($option_name, '');
        if ($encrypted_value === '') return $default;
        try {
            $key  = $this->get_crypto_key();
            $data = base64_decode($encrypted_value, true);
            if ($data === false || strlen($data) < 17) return $default;
            $iv = substr($data, 0, 16);
            $enc = substr($data, 16);
            $out = openssl_decrypt($enc, 'AES-256-CBC', $key, 0, $iv);
            return ($out !== false) ? $out : $default;
        } catch (Throwable $e) {
            error_log("Decryption error: " . $e->getMessage());
            return $default;
        }
    }

    private function verify_nonce(string $action): bool {
        return isset($_REQUEST['_wpnonce']) && wp_verify_nonce(sanitize_text_field($_REQUEST['_wpnonce']), $action);
    }

    private function is_valid_uuid(string $uuid): bool {
        return (bool) preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i', $uuid);
    }

    private function get_region_label(string $uuid): string {
        $uuid = trim($uuid);
        if ($uuid === '') {
            return '';
        }

        $normalized = strtolower($uuid);
        if (isset($this->region_labels[$normalized]) && $this->region_labels[$normalized] !== '') {
            return $this->region_labels[$normalized];
        }

        return $uuid;
    }

    // ---- Tables ----
    public function create_tables(): void {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        $ignore_table = $wpdb->prefix . 'market_ignore'; // legacy UUID-only
        $rules_table  = $wpdb->prefix . 'market_ignore_rules';
        $orders_table = $wpdb->prefix . 'market_orders';
        $logs_table   = $wpdb->prefix . 'market_delivery_logs';

        $sql_ignore = "CREATE TABLE IF NOT EXISTS $ignore_table (
            id int(11) NOT NULL AUTO_INCREMENT,
            prim_uuid varchar(36) NOT NULL,
            created_at timestamp DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY prim_uuid (prim_uuid)
        ) $charset_collate;";

        $sql_rules = "CREATE TABLE IF NOT EXISTS $rules_table (
            id int(11) NOT NULL AUTO_INCREMENT,
            rule_type varchar(20) NOT NULL,   -- uuid | name_exact | name_contains
            rule_value varchar(255) NOT NULL, -- lowercase for case-insensitive compare
            created_at timestamp DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY rule_unique (rule_type, rule_value)
        ) $charset_collate;";

        $sql_orders = "CREATE TABLE IF NOT EXISTS $orders_table (
            id int(11) NOT NULL AUTO_INCREMENT,
            buyer_uuid varchar(36) NOT NULL,
            seller_uuid varchar(36),
            prim_uuid varchar(36) NOT NULL,
            price decimal(10,2) NOT NULL,
            status varchar(20) NOT NULL DEFAULT 'pending',
            created_at timestamp DEFAULT CURRENT_TIMESTAMP,
            updated_at timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY buyer_uuid (buyer_uuid),
            KEY seller_uuid (seller_uuid),
            KEY status (status)
        ) $charset_collate;";

        $sql_logs = "CREATE TABLE IF NOT EXISTS $logs_table (
            id int(11) NOT NULL AUTO_INCREMENT,
            order_id int(11),
            buyer_uuid varchar(36) NOT NULL,
            prim_uuid varchar(36) NOT NULL,
            status varchar(20) NOT NULL,
            message text,
            created_at timestamp DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY order_id (order_id),
            KEY buyer_uuid (buyer_uuid)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql_ignore);
        dbDelta($sql_rules);
        dbDelta($sql_orders);
        dbDelta($sql_logs);
    }

    // ---- CPT ----
    public function register_cpt(): void {
        register_post_type('opensim_item', [
            'label' => 'OpenSim Items',
            'public' => true,
            'has_archive' => true,
            'supports' => ['title', 'editor', 'custom-fields', 'thumbnail'],
            'show_in_rest' => true,
            'menu_icon' => 'dashicons-store',
            'labels' => [
                'name' => 'OpenSim Items',
                'singular_name' => 'OpenSim Item',
                'add_new' => 'Add New Item',
                'add_new_item' => 'Add New OpenSim Item',
                'edit_item' => 'Edit OpenSim Item',
                'new_item' => 'New OpenSim Item',
                'view_item' => 'View OpenSim Item',
                'search_items' => 'Search Items',
            ]
        ]);
    }

    // ---- Editor Meta Boxes ----
    public function register_item_metaboxes(): void {
        add_meta_box(
            'osmp_item_details',
            'Marketplace Details',
            [$this, 'render_item_meta_box'],
            'opensim_item',
            'normal',
            'high'
        );
    }

    public function render_item_meta_box(WP_Post $post): void {
        wp_nonce_field('osmp_item_meta', 'osmp_item_meta_nonce');

        $price       = get_post_meta($post->ID, '_price', true);
        $forsale     = get_post_meta($post->ID, '_forsale', true);
        $seller_uuid = get_post_meta($post->ID, '_seller_uuid', true);
        $prim_uuid   = get_post_meta($post->ID, '_prim_uuid', true);
        $region_uuid = get_post_meta($post->ID, '_region_uuid', true);
        $texture_uuid = get_post_meta($post->ID, '_texture_uuid', true);
        $texture_url  = get_post_meta($post->ID, '_texture_url', true);

        $price = is_numeric($price) ? (float)$price : 0.0;
        $forsale = $forsale ? 1 : 0;

        echo '<table class="form-table">';
        echo '<tr><th><label for="osmp_price">Price</label></th><td>';
        echo '<input type="number" step="0.01" min="0" id="osmp_price" name="osmp_price" value="' . esc_attr(number_format($price, 2, '.', '')) . '" class="regular-text">';
        echo '</td></tr>';

        echo '<tr><th><label for="osmp_forsale">For sale</label></th><td>';
        echo '<label><input type="checkbox" id="osmp_forsale" name="osmp_forsale" value="1" ' . checked($forsale, 1, false) . '> Item is available for purchase</label>';
        echo '</td></tr>';

        echo '<tr><th><label for="osmp_seller_uuid">Seller UUID</label></th><td>';
        echo '<input type="text" id="osmp_seller_uuid" name="osmp_seller_uuid" value="' . esc_attr($seller_uuid) . '" class="regular-text" placeholder="Optional seller UUID">';
        echo '<p class="description">Optional. Leave empty to skip crediting a seller.</p>';
        echo '</td></tr>';

        echo '<tr><th>Prim UUID</th><td>';
        echo '<input type="text" readonly value="' . esc_attr($prim_uuid) . '" class="regular-text code">';
        echo '</td></tr>';

        echo '<tr><th>Region UUID</th><td>';
        echo '<input type="text" readonly value="' . esc_attr($region_uuid) . '" class="regular-text code">';
        echo '</td></tr>';

        echo '<tr><th><label for="osmp_texture_uuid">Texture UUID</label></th><td>';
        echo '<input type="text" id="osmp_texture_uuid" name="osmp_texture_uuid" value="' . esc_attr($texture_uuid) . '" class="regular-text" placeholder="Optional texture UUID">';
        echo '<p class="description">Provide an OpenSim texture UUID to pull previews via the configured proxy.</p>';
        echo '</td></tr>';

        echo '<tr><th><label for="osmp_texture_url">External Image URL</label></th><td>';
        echo '<input type="url" id="osmp_texture_url" name="osmp_texture_url" value="' . esc_attr($texture_url) . '" class="regular-text" placeholder="https://example.com/image.jpg">';
        echo '<p class="description">Used when no featured image or texture UUID is set.</p>';
        echo '</td></tr>';

        echo '</table>';
    }

    public function save_item_meta(int $post_id): void {
        if (!isset($_POST['osmp_item_meta_nonce']) || !wp_verify_nonce(sanitize_text_field($_POST['osmp_item_meta_nonce']), 'osmp_item_meta')) return;
        if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) return;
        if (wp_is_post_revision($post_id)) return;
        if (!current_user_can('edit_post', $post_id)) return;

        // Price
        if (isset($_POST['osmp_price'])) {
            $price = floatval($_POST['osmp_price']);
            if ($price < 0) $price = 0;
            update_post_meta($post_id, '_price', $price);
        }

        // For sale
        $forsale = isset($_POST['osmp_forsale']) ? '1' : '0';
        update_post_meta($post_id, '_forsale', $forsale);

        // Seller UUID (optional, must be valid or empty)
        if (isset($_POST['osmp_seller_uuid'])) {
            $seller_uuid = trim(sanitize_text_field($_POST['osmp_seller_uuid']));
            if ($seller_uuid === '' || $this->is_valid_uuid($seller_uuid)) {
                update_post_meta($post_id, '_seller_uuid', $seller_uuid);
            }
        }

        if (isset($_POST['osmp_texture_uuid'])) {
            $texture_uuid = trim(sanitize_text_field($_POST['osmp_texture_uuid']));
            if ($texture_uuid === '') {
                delete_post_meta($post_id, '_texture_uuid');
            } elseif ($this->is_valid_uuid($texture_uuid)) {
                update_post_meta($post_id, '_texture_uuid', $texture_uuid);
            }
        }

        if (isset($_POST['osmp_texture_url'])) {
            $texture_url = trim((string) $_POST['osmp_texture_url']);
            $clean_url = esc_url_raw($texture_url);
            if ($texture_url === '' || $clean_url === '') {
                delete_post_meta($post_id, '_texture_url');
            } else {
                update_post_meta($post_id, '_texture_url', $clean_url);
            }
        }
    }

    // ---- Admin columns ----
    public function add_admin_columns(array $cols): array {
        $new = [];
        foreach ($cols as $k => $v) {
            $new[$k] = $v;
            if ($k === 'title') {
                $new['osmp_price'] = 'Price';
                $new['osmp_forsale'] = 'For Sale';
                $new['osmp_prim_uuid'] = 'Prim UUID';
                $new['osmp_region'] = 'Region';
            }
        }
        return $new;
    }

    public function render_admin_columns(string $column, int $post_id): void {
        switch ($column) {
            case 'osmp_price':
                $price = get_post_meta($post_id, '_price', true);
                echo esc_html(is_numeric($price) ? number_format((float)$price, 2) : '');
                break;
            case 'osmp_forsale':
                $fs = get_post_meta($post_id, '_forsale', true);
                echo $fs ? '<span style="color:#0a0;font-weight:600">Yes</span>' : '<span style="color:#a00;">No</span>';
                break;
            case 'osmp_prim_uuid':
                $uuid = get_post_meta($post_id, '_prim_uuid', true);
                echo '<code>' . esc_html($uuid) . '</code>';
                break;
            case 'osmp_region':
                $uuid = get_post_meta($post_id, '_region_uuid', true);
                $label = get_post_meta($post_id, '_region_label', true);
                if ($label === '') {
                    $label = $this->get_region_label((string) $uuid);
                }
                $display = $label !== '' ? $label : $uuid;
                echo esc_html((string) $display);
                break;
        }
    }

    public function sortable_admin_columns(array $cols): array {
        $cols['osmp_price'] = 'osmp_price';
        $cols['osmp_forsale'] = 'osmp_forsale';
        return $cols;
    }

    public function handle_sorting(WP_Query $q): void {
        if (!is_admin() || !$q->is_main_query()) return;
        if ($q->get('post_type') !== 'opensim_item') return;

        $orderby = $q->get('orderby');
        if ($orderby === 'osmp_price') {
            $q->set('meta_key', '_price');
            $q->set('orderby', 'meta_value_num');
        } elseif ($orderby === 'osmp_forsale') {
            $q->set('meta_key', '_forsale');
            $q->set('orderby', 'meta_value_num');
        }
    }

    // ---- Shortcode (Buy Page) ----
    public function register_shortcodes(): void {
        add_shortcode('osmp_market', [$this, 'shortcode_market']);
    }

    private function get_user_balance(string $uuid): ?float {
        if (!$this->money_db || !$this->is_valid_uuid($uuid)) return null;
        try {
            $stmt = $this->money_db->prepare("SELECT balance FROM balances WHERE user = ?");
            if (!$stmt) return null;
            $stmt->bind_param('s', $uuid);
            if (!$stmt->execute()) { $stmt->close(); return null; }
            $stmt->bind_result($balance);
            $has = $stmt->fetch();
            $stmt->close();
            return $has ? (float)$balance : null;
        } catch (Throwable $e) {
            error_log('OpenSim Marketplace balance error: ' . $e->getMessage());
            return null;
        }
    }

    private function get_avatar_meta_keys(): array {
        $default_keys = [
            '_w4os_avatar_uuid',
            'w4os_uuid',
            'w4os_avatar_uuid',
            'avatar_uuid',
            'opensim_avatar_uuid',
            'os_avatar_uuid',
            '_os_avatar_uuid',
        ];

        $filtered_keys = apply_filters('osmp_avatar_uuid_meta_keys', $default_keys, $this);
        if (!is_array($filtered_keys)) {
            $filtered_keys = $default_keys;
        }

        $unique_keys = [];
        foreach ($filtered_keys as $key) {
            $key = trim((string) $key);
            if ($key !== '') {
                $unique_keys[$key] = true;
            }
        }

        return array_keys($unique_keys);
    }

    private function get_user_avatar_uuid(int $user_id): string {
        if ($user_id <= 0) {
            return '';
        }

        $meta_keys = $this->get_avatar_meta_keys();
        foreach ($meta_keys as $meta_key) {
            $value = (string) get_user_meta($user_id, $meta_key, true);
            if ($value !== '' && $this->is_valid_uuid($value)) {
                return $value;
            }
        }

        $fallback = apply_filters('osmp_avatar_uuid_fallback', '', $user_id, $meta_keys, $this);
        if (is_string($fallback) && $fallback !== '' && $this->is_valid_uuid($fallback)) {
            return $fallback;
        }

        return '';
    }

    private function get_avatar_name(string $uuid): ?string {
        if (!$this->os_db || !$this->is_valid_uuid($uuid)) return null;
        $cache_key = 'osmp_name_' . $uuid;
        $cached = get_transient($cache_key);
        if ($cached !== false) return $cached ?: null;
        try {
            foreach (['useraccounts', 'UserAccounts'] as $table) {
                $sql = "SELECT FirstName, LastName FROM {$table} WHERE PrincipalID = ? LIMIT 1";
                $stmt = $this->os_db->prepare($sql);
                if (!$stmt) continue;
                $stmt->bind_param('s', $uuid);
                if ($stmt->execute()) {
                    $res = $stmt->get_result();
                    if ($row = $res->fetch_assoc()) {
                        $name = trim(($row['FirstName'] ?? '') . ' ' . ($row['LastName'] ?? ''));
                        $name = $name !== '' ? $name : null;
                        set_transient($cache_key, $name ?: '', 12 * HOUR_IN_SECONDS);
                        $stmt->close();
                        return $name;
                    }
                }
                $stmt->close();
            }
        } catch (Throwable $e) {
            error_log('OpenSim Marketplace: avatar name lookup error: ' . $e->getMessage());
        }
        set_transient($cache_key, '', HOUR_IN_SECONDS);
        return null;
    }

    public function shortcode_market($atts): string {
        if (!is_array($atts)) $atts = [];
        $atts = shortcode_atts(['per_page' => 12, 'theme' => 'dark'], $atts, 'osmp_market');
        $theme = in_array(strtolower($atts['theme']), ['dark','light','auto'], true) ? strtolower($atts['theme']) : 'dark';

        $per_page = max(1, min(50, (int)$atts['per_page']));
        $page     = isset($_GET['mpg']) ? max(1, (int)$_GET['mpg']) : 1;
        $q        = isset($_GET['q']) ? sanitize_text_field($_GET['q']) : '';
        $region   = isset($_GET['region']) ? sanitize_text_field($_GET['region']) : '';
        $minp     = isset($_GET['minp']) ? floatval($_GET['minp']) : null;
        $maxp     = isset($_GET['maxp']) ? floatval($_GET['maxp']) : null;

        // Current user/visitor context
        $login_url = wp_login_url(get_permalink());
        $buyer_context = $this->resolve_buyer_context(true);
        $balance = $buyer_context['balance'] ?? null;
        $user_label = $buyer_context['display'] ?? null;
        $buyer_source = $buyer_context['source'] ?? null;
        $avatar_image_url = $buyer_context ? $this->get_texture_proxy_url($buyer_context['uuid']) : null;
        $avatar_login_nonce = wp_create_nonce('osmp_avatar_login');

        $args = [
            'post_type'      => 'opensim_item',
            'post_status'    => 'publish',
            'posts_per_page' => $per_page,
            'paged'          => $page,
            'orderby'        => 'title',
            'order'          => 'ASC',
            's'              => $q,
            'meta_query'     => [
                'relation' => 'AND',
                [ 'key' => '_forsale', 'value' => '1', 'compare' => '=' ]
            ]
        ];
        if ($region !== '') {
            $args['meta_query'][] = [ 'key' => '_region_uuid', 'value' => $region, 'compare' => '=' ];
        }
        if ($minp !== null) {
            $args['meta_query'][] = [ 'key' => '_price', 'value' => $minp, 'type' => 'NUMERIC', 'compare' => '>=' ];
        }
        if ($maxp !== null && $maxp >= 0) {
            $args['meta_query'][] = [ 'key' => '_price', 'value' => $maxp, 'type' => 'NUMERIC', 'compare' => '<=' ];
        }

        $regions = $this->get_all_regions();
        $query   = new WP_Query($args);
        $items   = $query->posts;

        $ajax_url = admin_url('admin-ajax.php');
        $nonce    = wp_create_nonce('osmp_purchase');

        ob_start();
        $instance_id = wp_unique_id('osmp-market-');
        ?>
        <div id="<?php echo esc_attr($instance_id); ?>" class="osmp-market osmp-theme-<?php echo esc_attr($theme); ?>">
            <div class="osmp-greet">
                <?php if ($buyer_context): ?>
                    <div class="osmp-greet-info">
                        <?php if ($avatar_image_url): ?>
                            <div class="osmp-greet-avatar">
                                <img src="<?php echo esc_url($avatar_image_url); ?>" alt="<?php echo esc_attr($user_label ?? 'Avatar'); ?>" loading="lazy">
                            </div>
                        <?php endif; ?>
                        <div class="osmp-greet-text">
                            <div class="osmp-greet-name"><strong>Hello,</strong> <?php echo esc_html($user_label ?? ''); ?></div>
                            <div class="osmp-greet-balance"><strong>Your balance:</strong> <span><?php echo ($balance !== null) ? esc_html(number_format((float) $balance, 2)) : '—'; ?></span></div>
                        </div>
                    </div>
                    <div class="osmp-greet-actions">
                        <?php if ($buyer_source === 'avatar'): ?>
                            <button type="button" class="osmp-btn osmp-btn-secondary osmp-avatar-logout">Log out</button>
                        <?php else: ?>
                            <a class="osmp-btn osmp-btn-secondary" href="<?php echo esc_url(wp_logout_url(get_permalink())); ?>">Log out</a>
                        <?php endif; ?>
                    </div>
                <?php else: ?>
                    <div class="osmp-greet-info osmp-greet-info--stack">
                        <div class="osmp-greet-name"><strong>Welcome!</strong> Sign in with your WordPress account or avatar UUID to buy.</div>
                        <div class="osmp-login-options">
                            <a class="osmp-btn" href="<?php echo esc_url($login_url); ?>">WordPress Login</a>
                            <form class="osmp-avatar-login" method="post" action="">
                                <label for="<?php echo esc_attr($instance_id); ?>-avatar-uuid">Avatar UUID</label>
                                <div class="osmp-avatar-login__row">
                                    <input type="text" id="<?php echo esc_attr($instance_id); ?>-avatar-uuid" name="avatar_uuid" maxlength="36" pattern="[0-9a-fA-F-]{36}" placeholder="00000000-0000-0000-0000-000000000000" autocomplete="off" inputmode="text" required>
                                    <button type="submit" class="osmp-btn">Sign in</button>
                                </div>
                                <p class="osmp-muted osmp-avatar-login__help">Your avatar UUID is stored securely in a cookie for quick checkout on this browser.</p>
                            </form>
                        </div>
                    </div>
                <?php endif; ?>
            </div>

            <form class="osmp-filters" method="get">
                <input type="text" name="q" value="<?php echo esc_attr($q); ?>" placeholder="Search name...">
                <select name="region">
                    <option value="">All regions</option>
                    <?php foreach ($regions as $region_uuid => $region_label): ?>
                        <option value="<?php echo esc_attr($region_uuid); ?>" <?php selected($region, $region_uuid); ?>><?php echo esc_html($region_label); ?></option>
                    <?php endforeach; ?>
                </select>
                <input type="number" step="0.01" min="0" name="minp" value="<?php echo ($minp !== null) ? esc_attr($minp) : ''; ?>" placeholder="Min price">
                <input type="number" step="0.01" min="0" name="maxp" value="<?php echo ($maxp !== null) ? esc_attr($maxp) : ''; ?>" placeholder="Max price">
                <input type="hidden" name="mpg" value="1">
                <button type="submit" class="osmp-btn">Filter</button>
            </form>

            <div class="osmp-grid">
                <?php if (empty($items)): ?>
                    <p class="osmp-muted">No items found.</p>
                <?php else: ?>
                    <?php foreach ($items as $post):
                        $item_id     = $post->ID;
                        $title       = get_the_title($item_id);
                        $price       = (float) get_post_meta($item_id, '_price', true);
                        $seller_uuid = get_post_meta($item_id, '_seller_uuid', true);
                        $seller_name = ($seller_uuid && $this->is_valid_uuid($seller_uuid)) ? ($this->get_avatar_name($seller_uuid) ?: null) : null;
                        $seller_label = $seller_name ?: 'Marketplace';
                        $region_uuid = get_post_meta($item_id, '_region_uuid', true);
                        $region_label = get_post_meta($item_id, '_region_label', true);
                        if ($region_label === '') {
                            $region_label = $this->get_region_label((string) $region_uuid);
                        }
                        $thumb_html  = get_the_post_thumbnail($item_id, 'medium', ['loading' => 'lazy', 'alt' => esc_attr($title)]);
                        if (!$thumb_html) {
                            $texture_uuid_meta = (string) get_post_meta($item_id, '_texture_uuid', true);
                            if ($texture_uuid_meta !== '' && $this->is_valid_uuid($texture_uuid_meta)) {
                                $proxy_url = $this->get_texture_proxy_url($texture_uuid_meta);
                                if ($proxy_url) {
                                    $thumb_html = sprintf('<img src="%s" alt="%s" loading="lazy" class="osmp-thumb-img" />', esc_url($proxy_url), esc_attr($title));
                                }
                            }
                        }
                        if (!$thumb_html) {
                            $texture_url_meta = (string) get_post_meta($item_id, '_texture_url', true);
                            if ($texture_url_meta !== '') {
                                $thumb_html = sprintf('<img src="%s" alt="%s" loading="lazy" class="osmp-thumb-img" />', esc_url($texture_url_meta), esc_attr($title));
                            }
                        }
                    ?>
                        <div class="osmp-card" data-item-id="<?php echo esc_attr($item_id); ?>">
                            <div class="osmp-thumb"><?php echo $thumb_html ?: '<div class="osmp-thumb--ph"></div>'; ?></div>
                            <h3 class="osmp-title" title="<?php echo esc_attr($title); ?>"><?php echo esc_html($title); ?></h3>
                            <div class="osmp-meta">
                                <span class="osmp-price"><?php echo esc_html(number_format($price, 2)); ?></span>
                                <span class="osmp-seller" title="Seller"><?php echo esc_html($seller_label); ?></span>
                                <span class="osmp-region" title="Region"><?php echo esc_html($region_label !== '' ? $region_label : ($region_uuid ?: '')); ?></span>
                            </div>
                            <div class="osmp-actions">
                                <?php if (!$buyer_context): ?>
                                    <button type="button" class="osmp-btn osmp-open-login">Sign in to buy</button>
                                <?php else: ?>
                                    <button type="button" class="osmp-btn osmp-buy" data-item="<?php echo esc_attr($item_id); ?>">Buy</button>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>

            <?php
            $total_pages = max(1, (int)$query->max_num_pages);
            if ($total_pages > 1): ?>
                <div class="osmp-pagination">
                    <?php
                    echo paginate_links([
                        'base'      => esc_url_raw(add_query_arg('mpg', '%#%')),
                        'format'    => '',
                        'prev_text' => '&laquo;',
                        'next_text' => '&raquo;',
                        'total'     => $total_pages,
                        'current'   => $page,
                        'add_args'  => [
                            'q'      => $q,
                            'region' => $region,
                            'minp'   => ($minp !== null ? $minp : null),
                            'maxp'   => ($maxp !== null ? $maxp : null),
                        ],
                    ]);
                    ?>
                </div>
            <?php endif; ?>

            <div class="osmp-msg" aria-live="polite"></div>
        </div>

        <style>
            /* Theme variables */
            .osmp-market {
                --bg: #0b0f14;
                --card: #111821;
                --field: #0f1620;
                --border: #22303c;
                --text: #e5edf5;
                --muted: #9aa7b4;
                --accent: #3ea6ff;
                --accent-contrast: #001421;
                --btn: #2563eb;
                --btn-contrast: #ffffff;
                --btn-hover: #1e50c7;
                --shadow: 0 6px 18px rgba(0,0,0,0.35);
                color: var(--text);
                background: var(--bg);
                padding: 1rem;
                border-radius: 10px;
            }
            .osmp-market a { color: var(--accent); }
            .osmp-market .osmp-muted { color: var(--muted); }

            /* Light theme overrides */
            .osmp-market.osmp-theme-light {
                --bg: #ffffff;
                --card: #ffffff;
                --field: #ffffff;
                --border: #dce2e8;
                --text: #111827;
                --muted: #6b7280;
                --accent: #2563eb;
                --accent-contrast: #eef2ff;
                --btn: #2563eb;
                --btn-contrast: #ffffff;
                --btn-hover: #1e50c7;
                --shadow: 0 6px 18px rgba(17,24,39,0.08);
            }
            /* Auto theme: light defaults + dark on prefers-color-scheme */
            .osmp-market.osmp-theme-auto {
                --bg: #ffffff;
                --card: #ffffff;
                --field: #ffffff;
                --border: #dce2e8;
                --text: #111827;
                --muted: #6b7280;
                --accent: #2563eb;
                --accent-contrast: #eef2ff;
                --btn: #2563eb;
                --btn-contrast: #ffffff;
                --btn-hover: #1e50c7;
                --shadow: 0 6px 18px rgba(17,24,39,0.08);
            }
            @media (prefers-color-scheme: dark) {
                .osmp-market.osmp-theme-auto {
                    --bg: #0b0f14;
                    --card: #111821;
                    --field: #0f1620;
                    --border: #22303c;
                    --text: #e5edf5;
                    --muted: #9aa7b4;
                    --accent: #3ea6ff;
                    --accent-contrast: #001421;
                    --btn: #2563eb;
                    --btn-contrast: #ffffff;
                    --btn-hover: #1e50c7;
                    --shadow: 0 6px 18px rgba(0,0,0,0.35);
                }
            }

            .osmp-greet {
                display:flex; flex-wrap:wrap; gap:1rem;
                align-items:center; justify-content:space-between;
                background: var(--card);
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: .75rem .9rem;
                box-shadow: var(--shadow);
            }
            .osmp-greet strong { color: var(--text); }
            .osmp-greet-info { display:flex; align-items:center; gap:1rem; flex:1; }
            .osmp-greet-info--stack { flex-direction: column; align-items:flex-start; gap:.75rem; }
            .osmp-greet-avatar { width:64px; height:64px; border-radius:50%; overflow:hidden; border:1px solid var(--border); background: var(--field); flex-shrink:0; }
            .osmp-greet-avatar img { width:100%; height:100%; object-fit:cover; display:block; }
            .osmp-greet-text { display:flex; flex-direction:column; gap:.3rem; }
            .osmp-greet-actions { display:flex; gap:.5rem; flex-wrap:wrap; justify-content:flex-end; }
            .osmp-login-options { display:flex; flex-wrap:wrap; gap:.75rem; align-items:flex-start; }
            .osmp-avatar-login { display:flex; flex-direction:column; gap:.4rem; background: var(--field); border:1px solid var(--border); padding:.6rem .75rem; border-radius:6px; box-shadow: var(--shadow); max-width:320px; }
            .osmp-avatar-login__row { display:flex; flex-wrap:wrap; gap:.5rem; align-items:center; }
            .osmp-avatar-login input[type="text"] { flex:1; min-width:220px; background: var(--bg); color: var(--text); border:1px solid var(--border); border-radius:6px; padding:.4rem .55rem; }
            .osmp-avatar-login input[type="text"]::placeholder { color: var(--muted); }
            .osmp-avatar-login label { font-size:.85rem; color: var(--muted); }
            .osmp-avatar-login__help { margin:0; font-size:.8rem; }
            .osmp-btn-secondary { background: transparent; color: var(--accent); border:1px solid var(--accent); }
            .osmp-btn-secondary:hover { background: var(--accent); color: var(--accent-contrast); }

            .osmp-filters {
                display: flex; flex-wrap: wrap; gap: .5rem; margin: 1rem 0;
                background: var(--card);
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: .6rem;
                box-shadow: var(--shadow);
            }
            .osmp-filters input[type="text"],
            .osmp-filters input[type="number"],
            .osmp-filters select {
                background: var(--field);
                color: var(--text);
                border: 1px solid var(--border);
                border-radius: 6px;
                padding: .45rem .55rem;
                outline: none;
            }
            .osmp-filters input::placeholder { color: var(--muted); }

            .osmp-btn, .osmp-actions .osmp-btn, .osmp-market .button, .osmp-market button {
                background: var(--btn);
                color: var(--btn-contrast);
                border: 1px solid transparent;
                padding: .45rem .7rem;
                border-radius: 6px;
                font-weight: 600;
                text-decoration: none;
                cursor: pointer;
                display: inline-block;
            }
            .osmp-btn:hover, .osmp-actions .osmp-btn:hover, .osmp-market .button:hover, .osmp-market button:hover {
                background: var(--btn-hover);
            }

            .osmp-grid {
                display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 1rem;
            }
            .osmp-card {
                background: var(--card);
                border: 1px solid var(--border);
                border-radius: 10px;
                padding: .75rem;
                display: flex; flex-direction: column; gap: .5rem;
                box-shadow: var(--shadow);
            }
            .osmp-thumb {
                background: var(--field);
                height: 180px;
                display:flex; align-items:center; justify-content:center;
                overflow:hidden; border-radius:6px;
                border: 1px solid var(--border);
            }
            .osmp-thumb img, .osmp-thumb .osmp-thumb-img { width: 100%; height: 100%; object-fit: cover; display: block; }
            .osmp-thumb--ph {
                width: 100%; height: 100%;
                background:
                    radial-gradient(transparent 1px, var(--field) 1px) 0 0/8px 8px,
                    radial-gradient(transparent 1px, var(--field) 1px) 4px 4px/8px 8px,
                    linear-gradient(var(--field), var(--field));
            }
            .osmp-title { font-size: 1rem; margin: 0; color: var(--text); }
            .osmp-meta { display:flex; justify-content: space-between; align-items:center; color: var(--muted); }
            .osmp-price { color: var(--text); font-weight: 700; }
            .osmp-price::before { content: '$'; opacity: .8; margin-right: 2px; }
            .osmp-seller { color: var(--muted); }

            .osmp-pagination { margin-top: 1rem; text-align: center; }
            .osmp-pagination .page-numbers { color: var(--text); background: var(--card); border: 1px solid var(--border); padding: .3rem .55rem; border-radius: 6px; margin: 0 2px; }
            .osmp-pagination .page-numbers.current { background: var(--btn); color: var(--btn-contrast); border-color: transparent; }

            .osmp-msg { margin-top: 1rem; font-weight: 600; color: var(--text); }
        </style>

        <script>
        (function() {
            const root = document.getElementById(<?php echo json_encode($instance_id); ?>);
            if (!root) return;
            const ajaxUrl = <?php echo json_encode($ajax_url); ?>;
            const nonce   = <?php echo json_encode($nonce); ?>;
            const loginNonce = <?php echo json_encode($avatar_login_nonce); ?>;
            const loginUrl = <?php echo json_encode($login_url); ?>;
            const msgEl   = root.querySelector('.osmp-msg');

            function setMsg(text, ok) {
                if (!msgEl) return;
                msgEl.textContent = text;
                msgEl.style.color = ok ? '#21c36b' : '#ff6b6b';
            }

            root.addEventListener('click', async function(e) {
                const loginBtn = e.target.closest('.osmp-open-login');
                if (loginBtn) {
                    e.preventDefault();
                    const loginForm = root.querySelector('.osmp-avatar-login');
                    if (loginForm) {
                        loginForm.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        const input = loginForm.querySelector('input[name="avatar_uuid"]');
                        if (input) {
                            input.focus();
                        }
                    } else if (loginUrl) {
                        window.location.href = loginUrl;
                    }
                    return;
                }

                const btn = e.target.closest('.osmp-buy');
                if (!btn) return;
                e.preventDefault();
                const itemId = btn.getAttribute('data-item');
                if (!itemId) return;

                btn.disabled = true;
                setMsg('Processing purchase...', true);

                try {
                    const form = new FormData();
                    form.append('action', 'osmp_purchase');
                    form.append('item_id', itemId);
                    form.append('_wpnonce', nonce);

                    const resp = await fetch(ajaxUrl, { method: 'POST', body: form, credentials: 'same-origin' });
                    const text = await resp.text();
                    let data = null;

                    if (text) {
                        try {
                            data = JSON.parse(text);
                        } catch (parseError) {
                            const trimmed = text.trim();
                            if (trimmed !== '') {
                                setMsg(trimmed, resp.ok);
                            } else {
                                setMsg(resp.ok ? 'Empty response from server' : 'Purchase failed (HTTP ' + resp.status + ')', false);
                            }
                            return;
                        }
                    }

                    if (data && typeof data === 'object' && 'success' in data) {
                        if (data.success) {
                            setMsg((data.data?.message || 'Purchase successful') + ' (Order #' + (data.data?.order_id || '?') + ')', true);
                        } else {
                            const err = data.data || data.message || 'Purchase failed';
                            setMsg(typeof err === 'string' ? err : 'Purchase failed', false);
                        }
                    } else {
                        const fallback = text && text.trim() !== '' ? text.trim() : 'Unexpected response from server';
                        setMsg(fallback, resp.ok);
                    }
                } catch (err) {
                    setMsg('Network or server error during purchase', false);
                } finally {
                    btn.disabled = false;
                }
            }, false);

            root.addEventListener('submit', async function(e) {
                const formEl = e.target;
                if (!formEl.classList || !formEl.classList.contains('osmp-avatar-login')) {
                    return;
                }

                e.preventDefault();
                const input = formEl.querySelector('input[name="avatar_uuid"]');
                if (!input) {
                    return;
                }

                const uuid = input.value.trim();
                if (!uuid) {
                    setMsg('Please enter your avatar UUID.', false);
                    return;
                }

                const submitBtn = formEl.querySelector('button[type="submit"]');
                if (submitBtn) {
                    submitBtn.disabled = true;
                }
                setMsg('Signing in...', true);

                try {
                    const formData = new FormData();
                    formData.append('action', 'osmp_avatar_login');
                    formData.append('_wpnonce', loginNonce);
                    formData.append('avatar_uuid', uuid);

                    const resp = await fetch(ajaxUrl, { method: 'POST', body: formData, credentials: 'same-origin' });
                    const text = await resp.text();
                    let data = null;

                    if (text) {
                        try {
                            data = JSON.parse(text);
                        } catch (parseError) {
                            const trimmed = text.trim();
                            if (trimmed !== '') {
                                setMsg(trimmed, false);
                            } else {
                                setMsg(resp.ok ? 'Empty response from server' : 'Login failed (HTTP ' + resp.status + ')', false);
                            }
                            return;
                        }
                    }

                    if (data && typeof data === 'object' && 'success' in data) {
                        if (data.success) {
                            const displayName = (data.data && (data.data.name || data.data.display)) || uuid;
                            setMsg('Signed in as ' + displayName + '. Reloading…', true);
                            setTimeout(() => { window.location.reload(); }, 500);
                        } else {
                            const err = data.data || data.message || 'Login failed';
                            setMsg(typeof err === 'string' ? err : 'Login failed', false);
                        }
                    } else {
                        const fallback = text && text.trim() !== '' ? text.trim() : 'Unexpected response from server';
                        setMsg(fallback, resp.ok);
                    }
                } catch (err) {
                    setMsg('Network or server error during login', false);
                } finally {
                    if (submitBtn) {
                        submitBtn.disabled = false;
                    }
                }
            }, false);

            const avatarLogout = root.querySelector('.osmp-avatar-logout');
            if (avatarLogout) {
                avatarLogout.addEventListener('click', async function(e) {
                    e.preventDefault();
                    if (avatarLogout.disabled) {
                        return;
                    }

                    avatarLogout.disabled = true;
                    setMsg('Signing out...', true);

                    try {
                        const form = new FormData();
                        form.append('action', 'osmp_avatar_logout');
                        form.append('_wpnonce', loginNonce);

                        const resp = await fetch(ajaxUrl, { method: 'POST', body: form, credentials: 'same-origin' });
                        const text = await resp.text();
                        let data = null;

                        if (text) {
                            try {
                                data = JSON.parse(text);
                            } catch (parseError) {
                                const trimmed = text.trim();
                                if (trimmed !== '') {
                                    setMsg(trimmed, false);
                                } else {
                                    setMsg(resp.ok ? 'Empty response from server' : 'Logout failed (HTTP ' + resp.status + ')', false);
                                }
                                return;
                            }
                        }

                        if (data && typeof data === 'object' && 'success' in data) {
                            if (data.success) {
                                setMsg('Signed out. Reloading…', true);
                                setTimeout(() => { window.location.reload(); }, 400);
                            } else {
                                const err = data.data || data.message || 'Logout failed';
                                setMsg(typeof err === 'string' ? err : 'Logout failed', false);
                            }
                        } else {
                            const fallback = text && text.trim() !== '' ? text.trim() : 'Unexpected response from server';
                            setMsg(fallback, resp.ok);
                        }
                    } catch (err) {
                        setMsg('Network or server error during logout', false);
                    } finally {
                        avatarLogout.disabled = false;
                    }
                }, false);
            }
        })();
        </script>
        <?php
        return ob_get_clean();
    }

    private function get_all_regions(): array {
        global $wpdb;

        $regions = [];
        foreach ($this->region_uuids as $uuid) {
            $regions[$uuid] = $this->get_region_label($uuid);
        }

        $sql = $wpdb->prepare(
            "SELECT DISTINCT uuid_meta.meta_value AS region_uuid,
                    COALESCE(label_meta.meta_value, uuid_meta.meta_value) AS region_label
             FROM {$wpdb->postmeta} uuid_meta
             INNER JOIN {$wpdb->posts} p ON p.ID = uuid_meta.post_id
             LEFT JOIN {$wpdb->postmeta} label_meta ON label_meta.post_id = uuid_meta.post_id AND label_meta.meta_key = %s
             WHERE uuid_meta.meta_key = %s AND p.post_type = 'opensim_item' AND p.post_status = 'publish'",
            '_region_label',
            '_region_uuid'
        );

        $rows = $wpdb->get_results($sql, ARRAY_A);
        if (is_array($rows)) {
            foreach ($rows as $row) {
                $uuid = isset($row['region_uuid']) ? (string) $row['region_uuid'] : '';
                if ($uuid === '') {
                    continue;
                }
                $label = isset($row['region_label']) ? (string) $row['region_label'] : $uuid;
                if (!isset($regions[$uuid])) {
                    $regions[$uuid] = $label !== '' ? $label : $uuid;
                }
            }
        }

        asort($regions, SORT_NATURAL | SORT_FLAG_CASE);
        return $regions;
    }

    // ---- Admin ----
    public function admin_menu(): void {
        add_menu_page('OpenSim Marketplace','OS Marketplace','manage_options','osmp_admin',[$this,'admin_page'],'dashicons-store');
        add_submenu_page('osmp_admin','Settings','Settings','manage_options','osmp_settings',[$this,'settings_page']);
    }

    public function admin_page(): void {
        if (!current_user_can('manage_options')) wp_die(__('You do not have sufficient permissions to access this page.'));

        $selected_sync_regions = [];
        if (isset($_POST['osmp_sync_regions']) && is_array($_POST['osmp_sync_regions'])) {
            foreach ($_POST['osmp_sync_regions'] as $candidate) {
                $candidate = trim(sanitize_text_field((string) $candidate));
                if ($candidate !== '') {
                    $selected_sync_regions[] = $candidate;
                }
            }
        }

        if (isset($_POST['osmp_remove_duplicates'])) {
            check_admin_referer('osmp_remove_duplicates', '_wpnonce_osmp_remove_duplicates');
            $dedupe_result = $this->remove_duplicate_items();

            $summary = sprintf(
                'Checked %d prim UUID groups. Removed %d duplicate items%s.',
                $dedupe_result['groups'],
                $dedupe_result['removed'],
                $dedupe_result['errors'] > 0
                    ? sprintf(' (%d items could not be trashed; see debug.log)', $dedupe_result['errors'])
                    : ''
            );

            $highlight = '';
            if (!empty($dedupe_result['prim_uuids'])) {
                $sample = array_slice($dedupe_result['prim_uuids'], 0, 5);
                $highlight = '<br><em>Affected prim UUIDs (sample): ' . esc_html(implode(', ', $sample)) . '</em>';
            }

            echo '<div class="notice notice-success"><p>' . esc_html($summary) . $highlight . '</p></div>';
        }

        // Manual sync trigger
        if (isset($_POST['osmp_sync_now']) && check_admin_referer('osmp_sync_now', '_wpnonce_osmp_sync')) {
            $regions_to_sync = [];
            foreach ($selected_sync_regions as $candidate) {
                if ($this->is_valid_uuid($candidate)) {
                    $regions_to_sync[] = $candidate;
                }
            }

            $this->sync_prims(200, !empty($regions_to_sync) ? $regions_to_sync : null);

            if (!empty($regions_to_sync)) {
                $labels = [];
                foreach ($regions_to_sync as $uuid) {
                    $label = $this->get_region_label($uuid);
                    $labels[] = $label !== '' ? $label : $uuid;
                }
                $human_list = implode(', ', array_map('esc_html', $labels));
                echo '<div class="notice notice-success"><p>Sync started for regions: ' . $human_list . '. Check debug.log for details.</p></div>';
            } else {
                echo '<div class="notice notice-success"><p>Sync started for all configured regions. Check debug.log for details.</p></div>';
            }
        }

        echo '<div class="wrap"><h1>OpenSim Marketplace Admin</h1>';

        $tab = isset($_GET['tab']) ? sanitize_key($_GET['tab']) : 'ignore';
        $allowed_tabs = ['ignore', 'orders', 'logs'];

        $region_options = [];
        foreach ($this->region_uuids as $uuid) {
            $region_options[$uuid] = $this->get_region_label($uuid);
        }
        if (empty($region_options)) {
            $region_options = $this->get_all_regions();
        }

        echo '<p><form method="post" style="display:inline-block;margin-right:10px">';
        wp_nonce_field('osmp_sync_now', '_wpnonce_osmp_sync');

        if (!empty($region_options)) {
            echo '<fieldset style="margin-bottom:8px;border:1px solid #ccd0d4;padding:8px 12px;background:#fff;">';
            echo '<legend style="font-weight:600;">Regions to sync (optional)</legend>';
            foreach ($region_options as $uuid => $label) {
                $uuid = (string) $uuid;
                $label = (string) $label;
                $checked = in_array($uuid, $selected_sync_regions, true) ? ' checked' : '';
                echo '<label style="display:inline-block;margin-right:12px;margin-bottom:4px;">';
                echo '<input type="checkbox" name="osmp_sync_regions[]" value="' . esc_attr($uuid) . '"' . $checked . '> ' . esc_html($label !== '' ? $label : $uuid);
                echo '</label>';
            }
            echo '<p class="description" style="margin:4px 0 0;">Leave all unchecked to sync every configured region.</p>';
            echo '</fieldset>';
        }

        echo '<input type="submit" class="button" name="osmp_sync_now" value="Sync Now">';
        echo '</form></p>';

        echo '<p><form method="post" style="display:inline-block;margin-right:10px">';
        wp_nonce_field('osmp_remove_duplicates', '_wpnonce_osmp_remove_duplicates');
        echo '<input type="submit" class="button" name="osmp_remove_duplicates" value="Remove Duplicate Items">';
        echo '</form></p>';

        echo '<h2 class="nav-tab-wrapper">';
        foreach ($allowed_tabs as $allowed_tab) {
            $active = ($tab === $allowed_tab) ? 'nav-tab-active' : '';
            $tab_url = add_query_arg(['page' => 'osmp_admin', 'tab' => $allowed_tab], admin_url('admin.php'));
            echo '<a class="nav-tab ' . esc_attr($active) . '" href="' . esc_url($tab_url) . '">' . esc_html(ucfirst($allowed_tab)) . '</a>';
        }
        echo '</h2>';

        switch ($tab) {
            case 'ignore': $this->render_ignore_list(); break;
            case 'orders': $this->render_orders(); break;
            case 'logs':   $this->render_logs(); break;
        }

        echo '</div>';
    }

    public function settings_page(): void {
        if (!current_user_can('manage_options')) wp_die(__('You do not have sufficient permissions to access this page.'));

        if (isset($_POST['submit']) && check_admin_referer('osmp_settings', '_wpnonce')) {
            update_option('osmp_delivery_api_url', esc_url_raw($_POST['osmp_delivery_api_url'] ?? ''));
            $regions_input = isset($_POST['osmp_region_uuids']) ? sanitize_textarea_field($_POST['osmp_region_uuids']) : '';
            update_option('osmp_region_uuids', $regions_input);
            update_option('osmp_region_uuid', sanitize_text_field($_POST['osmp_region_uuid'] ?? ''));
            update_option('osmp_os_db_host', sanitize_text_field($_POST['osmp_os_db_host']));
            update_option('osmp_os_db_user', sanitize_text_field($_POST['osmp_os_db_user']));
            update_option('osmp_os_db_name', sanitize_text_field($_POST['osmp_os_db_name']));
            update_option('osmp_money_db_host', sanitize_text_field($_POST['osmp_money_db_host']));
            update_option('osmp_money_db_user', sanitize_text_field($_POST['osmp_money_db_user']));
            update_option('osmp_money_db_name', sanitize_text_field($_POST['osmp_money_db_name']));
            update_option('osmp_texture_proxy_template', sanitize_text_field($_POST['osmp_texture_proxy_template'] ?? ''));

            if (!empty($_POST['osmp_delivery_api_password'])) {
                update_option('osmp_delivery_api_password', $this->encrypt_option(sanitize_text_field($_POST['osmp_delivery_api_password'])));
            }

            if (!empty($_POST['osmp_os_db_pass'])) {
                update_option('osmp_os_db_pass', $this->encrypt_option(sanitize_text_field($_POST['osmp_os_db_pass'])));
            }
            if (!empty($_POST['osmp_money_db_pass'])) {
                update_option('osmp_money_db_pass', $this->encrypt_option(sanitize_text_field($_POST['osmp_money_db_pass'])));
            }

            $this->init_config();
            $this->init_database_connections();
            echo '<div class="notice notice-success"><p>Settings saved! Database connections will be refreshed.</p></div>';
        }

        ?>
        <div class="wrap">
            <h1>OpenSim Marketplace Settings</h1>
            <form method="post" action="">
                <?php wp_nonce_field('osmp_settings'); ?>

                <h2>Delivery API Configuration</h2>
                <table class="form-table">
                    <tr>
                        <th><label for="osmp_delivery_api_url">Delivery API URL</label></th>
                        <td>
                            <input type="url" id="osmp_delivery_api_url" name="osmp_delivery_api_url" value="<?php echo esc_attr(get_option('osmp_delivery_api_url', 'http://i.let-us.cyou:2023/send')); ?>" class="regular-text" />
                            <p class="description">Base URL for the delivery service. Requests will be sent with avatar and object identifiers.</p>
                        </td>
                    </tr>
                    <tr>
                        <th><label for="osmp_delivery_api_password">Delivery API Password</label></th>
                        <td>
                            <input type="password" id="osmp_delivery_api_password" name="osmp_delivery_api_password" value="" class="regular-text" placeholder="Leave blank to keep current password" />
                            <p class="description">Shared secret included in delivery requests as the <code>pass</code> parameter.</p>
                        </td>
                    </tr>
                </table>

                <h2>Avatar Login &amp; Media</h2>
                <table class="form-table">
                    <tr>
                        <th><label for="osmp_texture_proxy_template">Texture Proxy URL</label></th>
                        <td>
                            <input type="text" id="osmp_texture_proxy_template" name="osmp_texture_proxy_template" value="<?php echo esc_attr(get_option('osmp_texture_proxy_template', '')); ?>" class="regular-text" placeholder="https://proxy.example/texture/{uuid}" />
                            <p class="description">Used to display avatar portraits and item previews from UUIDs. Include <code>{uuid}</code> where the texture UUID should be inserted. If omitted, the UUID will be appended to the end of the URL.</p>
                        </td>
                    </tr>
                </table>

                <h2>Region Synchronisation</h2>
                <table class="form-table">
                    <tr>
                        <th><label for="osmp_region_uuids">Region UUIDs</label></th>
                        <td>
                            <textarea id="osmp_region_uuids" name="osmp_region_uuids" rows="4" class="large-text code" placeholder="e.g. c6baa58b-59a4-4a02-9907-6baaf6cfead7&#10;another-region-uuid|Main Store&#10;third-region-uuid|Outlet|https://grid.example/send"><?php echo esc_textarea((string) get_option('osmp_region_uuids', get_option('osmp_region_uuid', ''))); ?></textarea>
                            <p class="description">Provide one region UUID per line. Optionally append a friendly name after a pipe (<code>|</code>) to label the region in the marketplace (e.g. <code>uuid|Main Store</code>). Add a second pipe followed by a delivery API base URL to override the global endpoint for that region (e.g. <code>uuid||https://grid.example/send</code>).</p>
                        </td>
                    </tr>
                    <tr>
                        <th><label for="osmp_region_uuid">Default Region UUID (legacy)</label></th>
                        <td>
                            <input type="text" id="osmp_region_uuid" name="osmp_region_uuid" value="<?php echo esc_attr(get_option('osmp_region_uuid')); ?>" class="regular-text" />
                            <p class="description">Optional fallback used when no multi-region list is provided.</p>
                        </td>
                    </tr>
                </table>

                <h2>OpenSim Database Configuration</h2>
                <table class="form-table">
                    <tr><th><label for="osmp_os_db_host">Host</label></th><td><input type="text" id="osmp_os_db_host" name="osmp_os_db_host" value="<?php echo esc_attr(get_option('osmp_os_db_host')); ?>" class="regular-text" placeholder="localhost" /></td></tr>
                    <tr><th><label for="osmp_os_db_user">Username</label></th><td><input type="text" id="osmp_os_db_user" name="osmp_os_db_user" value="<?php echo esc_attr(get_option('osmp_os_db_user')); ?>" class="regular-text" /></td></tr>
                    <tr><th><label for="osmp_os_db_pass">Password</label></th><td><input type="password" id="osmp_os_db_pass" name="osmp_os_db_pass" value="" class="regular-text" placeholder="Leave empty to keep current password" /></td></tr>
                    <tr><th><label for="osmp_os_db_name">Database Name</label></th><td><input type="text" id="osmp_os_db_name" name="osmp_os_db_name" value="<?php echo esc_attr(get_option('osmp_os_db_name', 'opensim')); ?>" class="regular-text" /></td></tr>
                </table>

                <h2>Money Database Configuration</h2>
                <table class="form-table">
                    <tr><th><label for="osmp_money_db_host">Host</label></th><td><input type="text" id="osmp_money_db_host" name="osmp_money_db_host" value="<?php echo esc_attr(get_option('osmp_money_db_host')); ?>" class="regular-text" placeholder="localhost" /></td></tr>
                    <tr><th><label for="osmp_money_db_user">Username</label></th><td><input type="text" id="osmp_money_db_user" name="osmp_money_db_user" value="<?php echo esc_attr(get_option('osmp_money_db_user')); ?>" class="regular-text" /></td></tr>
                    <tr><th><label for="osmp_money_db_pass">Password</label></th><td><input type="password" id="osmp_money_db_pass" name="osmp_money_db_pass" value="" class="regular-text" placeholder="Leave empty to keep current password" /></td></tr>
                    <tr><th><label for="osmp_money_db_name">Database Name</label></th><td><input type="text" id="osmp_money_db_name" name="osmp_money_db_name" value="<?php echo esc_attr(get_option('osmp_money_db_name', 'money')); ?>" class="regular-text" /></td></tr>
                </table>

                <h3>Database Connection Status</h3>
                <table class="form-table">
                    <tr><th>OpenSim DB</th><td><?php echo ($this->os_db && $this->os_db->ping()) ? '<span style="color:#0a0;">✓ Connected</span>' : '<span style="color:#a00;">✗ Not Connected</span>'; ?></td></tr>
                    <tr><th>Money DB</th><td><?php echo ($this->money_db && $this->money_db->ping()) ? '<span style="color:#0a0;">✓ Connected</span>' : '<span style="color:#a00;">✗ Not Connected</span>'; ?></td></tr>
                </table>

                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }

    // ---- Helper: load ignore sets ----
    private function get_ignore_sets(): array {
        global $wpdb;
        $legacy_ignore = []; $uuid_rules = []; $name_exact = []; $name_contains = [];
        try {
            $legacy_ignore = array_map('strtolower', (array)$wpdb->get_col("SELECT prim_uuid FROM `{$wpdb->prefix}market_ignore`"));
            $rules = $wpdb->get_results("SELECT rule_type, rule_value FROM `{$wpdb->prefix}market_ignore_rules`");
            foreach ((array)$rules as $r) {
                $val = strtolower((string)$r->rule_value);
                if ($r->rule_type === 'uuid') $uuid_rules[] = $val;
                elseif ($r->rule_type === 'name_exact') $name_exact[] = $val;
                elseif ($r->rule_type === 'name_contains') $name_contains[] = $val;
            }
        } catch (Throwable $e) {
            error_log('OpenSim Marketplace: failed loading ignore sets: ' . $e->getMessage());
        }
        return ['legacy_ignore' => $legacy_ignore, 'uuid_rules' => $uuid_rules, 'name_exact' => $name_exact, 'name_contains' => $name_contains];
    }

    // ---- Ignore List (rules + legacy) ----
    private function render_ignore_list(): void {
        global $wpdb;
        $legacy_table = $wpdb->prefix . 'market_ignore';
        $rules_table  = $wpdb->prefix . 'market_ignore_rules';

        // Bulk: trash all ignored items
        if (isset($_POST['osmp_trash_ignored']) && check_admin_referer('osmp_trash_ignored', '_wpnonce_osmp_trash_ignored')) {
            $result = $this->bulk_trash_ignored_items();
            $msg = sprintf('Trashed %d items. Already trashed: %d. Remaining matches may require another run.', $result['trashed'], $result['already_trashed']);
            echo '<div class="notice notice-success"><p>' . esc_html($msg) . '</p></div>';
        }

        // Add rule
        if (isset($_POST['osmp_add_rule']) && check_admin_referer('osmp_add_rule', '_wpnonce_osmp_add_rule')) {
            $rule_type  = isset($_POST['rule_type']) ? sanitize_key($_POST['rule_type']) : '';
            $rule_value = isset($_POST['rule_value']) ? trim(sanitize_text_field($_POST['rule_value'])) : '';

            $allowed = ['uuid', 'name_exact', 'name_contains'];
            if (!in_array($rule_type, $allowed, true)) {
                echo '<div class="notice notice-error"><p>Invalid rule type.</p></div>';
            } elseif ($rule_value === '') {
                echo '<div class="notice notice-error"><p>Rule value cannot be empty.</p></div>';
            } else {
                $store_value = strtolower($rule_value);
                if ($rule_type === 'uuid' && !$this->is_valid_uuid($rule_value)) {
                    echo '<div class="notice notice-error"><p>Invalid UUID format.</p></div>';
                } else {
                    $inserted = $wpdb->insert($rules_table, ['rule_type' => $rule_type, 'rule_value' => $store_value], ['%s','%s']);
                    if ($inserted !== false) echo '<div class="notice notice-success"><p>Ignore rule added.</p></div>';
                    else echo '<div class="notice notice-error"><p>Rule already exists or failed to add.</p></div>';
                }
            }
        }

        // Delete rule
        if (isset($_POST['osmp_del_rule']) && check_admin_referer('osmp_del_rule', '_wpnonce_osmp_del_rule')) {
            $rid = isset($_POST['rule_id']) ? (int)$_POST['rule_id'] : 0;
            if ($rid > 0) {
                $res = $wpdb->delete($rules_table, ['id' => $rid], ['%d']);
                if ($res !== false) echo '<div class="notice notice-success"><p>Rule removed.</p></div>';
                else echo '<div class="notice notice-error"><p>Failed to remove rule.</p></div>';
            }
        }

        // Legacy add/remove (UUID only)
        if (isset($_POST['ignore_add']) && $this->verify_nonce('osmp_ignore_add')) {
            $prim_uuid = sanitize_text_field($_POST['prim_uuid']);
            if (!$this->is_valid_uuid($prim_uuid)) {
                echo '<div class="notice notice-error"><p>Invalid UUID format</p></div>';
            } else {
                $result = $wpdb->insert($legacy_table, ['prim_uuid' => $prim_uuid], ['%s']);
                if ($result !== false) echo '<div class="notice notice-success"><p>Prim added to legacy ignore list</p></div>';
                else echo '<div class="notice notice-error"><p>Failed to add prim (may already exist)</p></div>';
            }
        }
        if (isset($_POST['ignore_remove']) && $this->verify_nonce('osmp_ignore_remove')) {
            $id = intval($_POST['id']);
            $result = $wpdb->delete($legacy_table, ['id' => $id], ['%d']);
            if ($result !== false) echo '<div class="notice notice-success"><p>Prim removed from legacy ignore list</p></div>';
            else echo '<div class="notice notice-error"><p>Failed to remove prim</p></div>';
        }

        // Bulk action UI
        echo '<h3>Bulk actions</h3>';
        echo '<form method="POST" style="margin-bottom:12px">';
        wp_nonce_field('osmp_trash_ignored', '_wpnonce_osmp_trash_ignored');
        echo '<p>This will move all existing marketplace posts that match any ignore rule (UUID or Name) to Trash. Up to 500 per run.</p>';
        echo '<input type="submit" name="osmp_trash_ignored" class="button button-secondary" value="Trash all ignored items">';
        echo '</form>';

        // ------- Add Ignore Rule UI -------
        echo '<h3>Add Ignore Rule</h3>';
        echo '<form method="POST" style="margin-bottom:10px">';
        wp_nonce_field('osmp_add_rule', '_wpnonce_osmp_add_rule');
        echo '<label><input type="radio" name="rule_type" value="uuid" checked> UUID (exact)</label> ';
        echo '<label><input type="radio" name="rule_type" value="name_exact"> Name (exact)</label> ';
        echo '<label><input type="radio" name="rule_type" value="name_contains"> Name (contains)</label> ';
        echo '<br><input name="rule_value" placeholder="Enter UUID or Name" class="regular-text" required>';
        echo ' <input type="submit" name="osmp_add_rule" class="button button-primary" value="Add Rule">';
        echo '</form>';

        // ------- Filter rules -------
        $rsearch  = isset($_GET['rsearch']) ? sanitize_text_field($_GET['rsearch']) : '';
        $rtype    = isset($_GET['rtype']) ? sanitize_key($_GET['rtype']) : '';
        $rfrom    = isset($_GET['rfrom']) ? sanitize_text_field($_GET['rfrom']) : '';
        $rto      = isset($_GET['rto']) ? sanitize_text_field($_GET['rto']) : '';
        $rpp      = isset($_GET['rpp']) ? max(5, min(200, (int)$_GET['rpp'])) : 50;
        $rpaged   = isset($_GET['rpaged']) ? max(1, (int)$_GET['rpaged']) : 1;
        $roffset  = ($rpaged - 1) * $rpp;

        $conds = []; $vals = [];
        if ($rsearch !== '') { $conds[] = "rule_value LIKE %s"; $vals[] = '%' . $wpdb->esc_like(strtolower($rsearch)) . '%'; }
        if (in_array($rtype, ['uuid','name_exact','name_contains'], true)) { $conds[] = "rule_type = %s"; $vals[] = $rtype; }
        if ($rfrom !== '') { $conds[] = "DATE(created_at) >= %s"; $vals[] = $rfrom; }
        if ($rto !== '') { $conds[] = "DATE(created_at) <= %s"; $vals[] = $rto; }

        $where = $conds ? (' WHERE ' . implode(' AND ', $conds)) : '';
        $count_sql = "SELECT COUNT(*) FROM `{$rules_table}`{$where}";
        $list_sql  = "SELECT * FROM `{$rules_table}`{$where} ORDER BY created_at DESC, id DESC LIMIT %d OFFSET %d";

        if ($vals) {
            $rules_total = (int)$wpdb->get_var($wpdb->prepare($count_sql, ...$vals));
            $rules_list  = $wpdb->get_results($wpdb->prepare($list_sql, ...array_merge($vals, [$rpp, $roffset])));
        } else {
            $rules_total = (int)$wpdb->get_var($count_sql);
            $rules_list  = $wpdb->get_results($wpdb->prepare($list_sql, $rpp, $roffset));
        }

        // Rules filter form
        echo '<h3>Ignore Rules</h3>';
        echo '<form method="GET" style="margin-bottom:10px">';
        echo '<input type="hidden" name="page" value="osmp_admin">';
        echo '<input type="hidden" name="tab" value="ignore">';
        echo '<input type="text" name="rsearch" value="' . esc_attr($rsearch) . '" placeholder="Search value (case-insensitive)"> ';
        echo '<select name="rtype"><option value="">All types</option>';
        foreach (['uuid'=>'UUID','name_exact'=>'Name (exact)','name_contains'=>'Name (contains)'] as $k=>$label) {
            echo '<option value="' . esc_attr($k) . '"' . selected($rtype, $k, false) . '>' . esc_html($label) . '</option>';
        }
        echo '</select> ';
        echo ' From: <input type="date" name="rfrom" value="' . esc_attr($rfrom) . '">';
        echo ' To: <input type="date" name="rto" value="' . esc_attr($rto) . '">';
        echo ' Per page: <input type="number" min="5" max="200" name="rpp" value="' . intval($rpp) . '" style="width:80px"> ';
        echo ' <input type="submit" class="button" value="Apply">';
        echo ' <a class="button" href="' . esc_url(add_query_arg(['page' => 'osmp_admin', 'tab' => 'ignore'], admin_url('admin.php'))) . '">Reset</a>';
        echo '</form>';

        // Rules table
        echo '<table class="wp-list-table widefat fixed striped">';
        echo '<thead><tr><th>ID</th><th>Type</th><th>Value</th><th>Added</th><th>Action</th></tr></thead><tbody>';
        if (!empty($rules_list)) {
            foreach ($rules_list as $r) {
                echo '<tr>';
                echo '<td>' . intval($r->id) . '</td>';
                echo '<td>' . esc_html($r->rule_type) . '</td>';
                echo '<td><code>' . esc_html($r->rule_value) . '</code></td>';
                echo '<td>' . esc_html($r->created_at) . '</td>';
                echo '<td><form method="POST" style="display:inline">';
                wp_nonce_field('osmp_del_rule', '_wpnonce_osmp_del_rule');
                echo '<input type="hidden" name="rule_id" value="' . intval($r->id) . '">';
                echo '<input type="submit" name="osmp_del_rule" class="button button-secondary" value="Remove" onclick="return confirm(\'Remove this rule?\')">';
                echo '</form></td>';
                echo '</tr>';
            }
        } else {
            echo '<tr><td colspan="5">No rules found for the selected filters.</td></tr>';
        }
        echo '</tbody></table>';

        $rules_pages = max(1, (int)ceil($rules_total / $rpp));
        if ($rules_pages > 1) {
            echo '<div class="tablenav"><div class="tablenav-pages">';
            echo paginate_links([
                'base'      => add_query_arg('rpaged', '%#%'),
                'format'    => '',
                'prev_text' => __('&laquo;'),
                'next_text' => __('&raquo;'),
                'total'     => $rules_pages,
                'current'   => $rpaged
            ]);
            echo '</div></div>';
        }

        // ------- Legacy UUID ignore (backward compatibility) -------
        $search   = isset($_GET['uuid']) ? sanitize_text_field($_GET['uuid']) : '';
        $date_from = isset($_GET['from']) ? sanitize_text_field($_GET['from']) : '';
        $date_to   = isset($_GET['to']) ? sanitize_text_field($_GET['to']) : '';
        $per_page  = isset($_GET['pp']) ? max(5, min(200, (int)$_GET['pp'])) : 50;
        $paged     = isset($_GET['paged']) ? max(1, (int)$_GET['paged']) : 1;
        $offset    = ($paged - 1) * $per_page;

        $conds2 = []; $vals2 = [];
        if ($search !== '') { $conds2[] = "prim_uuid LIKE %s"; $vals2[] = '%' . $wpdb->esc_like($search) . '%'; }
        if ($date_from !== '') { $conds2[] = "DATE(created_at) >= %s"; $vals2[] = $date_from; }
        if ($date_to !== '') { $conds2[] = "DATE(created_at) <= %s"; $vals2[] = $date_to; }
        $where2 = $conds2 ? (' WHERE ' . implode(' AND ', $conds2)) : '';

        $count_sql2 = "SELECT COUNT(*) FROM `{$legacy_table}`{$where2}";
        $list_sql2  = "SELECT * FROM `{$legacy_table}`{$where2} ORDER BY created_at DESC LIMIT %d OFFSET %d";

        if ($vals2) {
            $total = (int)$wpdb->get_var($wpdb->prepare($count_sql2, ...$vals2));
            $list  = $wpdb->get_results($wpdb->prepare($list_sql2, ...array_merge($vals2, [$per_page, $offset])));
        } else {
            $total = (int)$wpdb->get_var($count_sql2);
            $list  = $wpdb->get_results($wpdb->prepare($list_sql2, $per_page, $offset));
        }

        echo '<h3>Legacy UUID Ignore List</h3>';
        echo '<form method="POST">';
        wp_nonce_field('osmp_ignore_add');
        echo '<input name="prim_uuid" placeholder="Prim UUID (e.g., 12345678-1234-1234-1234-123456789012)" required pattern="[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}" class="regular-text"> ';
        echo '<input type="submit" name="ignore_add" class="button" value="Add">';
        echo '</form>';

        echo '<form method="GET" style="margin:10px 0">';
        echo '<input type="hidden" name="page" value="osmp_admin"><input type="hidden" name="tab" value="ignore">';
        echo '<input type="text" name="uuid" value="' . esc_attr($search) . '" placeholder="Search UUID"> ';
        echo 'From: <input type="date" name="from" value="' . esc_attr($date_from) . '"> ';
        echo 'To: <input type="date" name="to" value="' . esc_attr($date_to) . '"> ';
        echo 'Per page: <input type="number" min="5" max="200" name="pp" value="' . intval($per_page) . '" style="width:80px"> ';
        echo '<input type="submit" class="button" value="Apply">';
        echo '</form>';

        echo '<table class="wp-list-table widefat fixed striped">';
        echo '<thead><tr><th>ID</th><th>Prim UUID</th><th>Added</th><th>Action</th></tr></thead><tbody>';
        foreach ($list as $item) {
            echo '<tr>';
            echo '<td>' . intval($item->id) . '</td>';
            echo '<td><code>' . esc_html($item->prim_uuid) . '</code></td>';
            echo '<td>' . esc_html($item->created_at) . '</td>';
            echo '<td><form method="POST" style="display:inline">';
            wp_nonce_field('osmp_ignore_remove');
            echo '<input type="hidden" name="id" value="' . intval($item->id) . '">';
            echo '<input type="submit" name="ignore_remove" class="button button-secondary" value="Remove" onclick="return confirm(\'Are you sure?\')">';
            echo '</form></td>';
            echo '</tr>';
        }
        if (empty($list)) echo '<tr><td colspan="4">No entries.</td></tr>';
        echo '</tbody></table>';

        $total_pages = max(1, (int)ceil($total / $per_page));
        if ($total_pages > 1) {
            echo '<div class="tablenav"><div class="tablenav-pages">';
            echo paginate_links([
                'base'      => add_query_arg('paged', '%#%'),
                'format'    => '',
                'prev_text' => __('&laquo;'),
                'next_text' => __('&raquo;'),
                'total'     => $total_pages,
                'current'   => $paged
            ]);
            echo '</div></div>';
        }
    }

    // Bulk trash ignored posts
    private function bulk_trash_ignored_items(): array {
        global $wpdb;
        $sets = $this->get_ignore_sets();

        $uuid_list     = array_values(array_unique(array_filter(array_merge($sets['legacy_ignore'] ?? [], $sets['uuid_rules'] ?? []))));
        $name_exact    = array_values(array_unique(array_filter($sets['name_exact'] ?? [])));
        $name_contains = array_values(array_unique(array_filter($sets['name_contains'] ?? [])));

        $post_type = 'opensim_item';
        $limit = 500;
        $ids = [];

        if (!empty($uuid_list)) {
            $placeholders = implode(',', array_fill(0, count($uuid_list), '%s'));
            $sql = "
                SELECT p.ID
                FROM {$wpdb->posts} p
                INNER JOIN {$wpdb->postmeta} pm ON pm.post_id = p.ID
                WHERE p.post_type = %s
                  AND p.post_status NOT IN ('trash','auto-draft')
                  AND pm.meta_key = '_prim_uuid'
                  AND LOWER(pm.meta_value) IN ($placeholders)
                LIMIT %d
            ";
            $params = array_merge([$post_type], $uuid_list, [$limit]);
            $ids = array_merge($ids, (array)$wpdb->get_col($wpdb->prepare($sql, ...$params)));
        }

        if (count($ids) < $limit && !empty($name_exact)) {
            $remaining = $limit - count($ids);
            $placeholders = implode(',', array_fill(0, count($name_exact), '%s'));
            $sql = "
                SELECT p.ID
                FROM {$wpdb->posts} p
                WHERE p.post_type = %s
                  AND p.post_status NOT IN ('trash','auto-draft')
                  AND LOWER(p.post_title) IN ($placeholders)
                LIMIT %d
            ";
            $params = array_merge([$post_type], $name_exact, [$remaining]);
            $ids = array_merge($ids, (array)$wpdb->get_col($wpdb->prepare($sql, ...$params)));
        }

        if (count($ids) < $limit && !empty($name_contains)) {
            $remaining = $limit - count($ids);
            $or = []; $vals = [];
            foreach ($name_contains as $needle) { $or[] = "LOWER(p.post_title) LIKE %s"; $vals[] = '%' . $wpdb->esc_like($needle) . '%'; }
            $where_like = implode(' OR ', $or);
            $sql = "
                SELECT p.ID
                FROM {$wpdb->posts} p
                WHERE p.post_type = %s
                  AND p.post_status NOT IN ('trash','auto-draft')
                  AND ($where_like)
                LIMIT %d
            ";
            $params = array_merge([$post_type], $vals, [$remaining]);
            $ids = array_merge($ids, (array)$wpdb->get_col($wpdb->prepare($sql, ...$params)));
        }

        $ids = array_values(array_unique(array_map('intval', $ids)));

        $trashed = 0; $already = 0;
        foreach ($ids as $pid) {
            $status = get_post_status($pid);
            if ($status === 'trash') { $already++; continue; }
            $res = wp_trash_post($pid);
            if ($res) $trashed++;
        }

        return ['trashed' => $trashed, 'already_trashed' => $already];
    }

    // ---- Orders ----
    private function render_orders(): void {
        global $wpdb;
        $table = $wpdb->prefix . 'market_orders';

        if (isset($_POST['redeliver']) && $this->verify_nonce('osmp_redeliver')) {
            $order_id = intval($_POST['order_id']);
            $this->handle_redelivery($order_id);
        }

        $per_page = 50;
        $paged = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
        $offset = ($paged - 1) * $per_page;

        $total_orders = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$table}`");
        $orders = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM `{$table}` ORDER BY created_at DESC LIMIT %d OFFSET %d",
            $per_page, $offset
        ));

        echo '<h3>Orders Management</h3>';
        echo '<table class="wp-list-table widefat fixed striped">';
        echo '<thead><tr><th>ID</th><th>Buyer UUID</th><th>Seller UUID</th><th>Prim UUID</th><th>Price</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead><tbody>';

        foreach ($orders as $order) {
            echo '<tr>';
            echo '<td>' . intval($order->id) . '</td>';
            echo '<td><code>' . esc_html($order->buyer_uuid) . '</code></td>';
            echo '<td><code>' . esc_html($order->seller_uuid ?: 'N/A') . '</code></td>';
            echo '<td><code>' . esc_html($order->prim_uuid) . '</code></td>';
            echo '<td>' . esc_html(number_format((float)$order->price, 2)) . '</td>';
            echo '<td><span class="status-' . esc_attr($order->status) . '">' . esc_html($order->status) . '</span></td>';
            echo '<td>' . esc_html($order->created_at) . '</td>';
            echo '<td>';
            if ($order->status !== 'delivered') {
                echo '<form method="POST" style="display:inline">';
                wp_nonce_field('osmp_redeliver');
                echo '<input type="hidden" name="order_id" value="' . intval($order->id) . '">';
                echo '<input type="submit" name="redeliver" class="button button-primary" value="Redeliver">';
                echo '</form>';
            }
            echo '</td></tr>';
        }

        if (empty($orders)) echo '<tr><td colspan="8">No orders yet.</td></tr>';
        echo '</tbody></table>';

        $total_pages = max(1, (int)ceil($total_orders / $per_page));
        if ($total_pages > 1) {
            echo '<div class="tablenav"><div class="tablenav-pages">';
            echo paginate_links([
                'base'      => add_query_arg('paged', '%#%'),
                'format'    => '',
                'prev_text' => __('&laquo;'),
                'next_text' => __('&raquo;'),
                'total'     => $total_pages,
                'current'   => $paged
            ]);
            echo '</div></div>';
        }
    }

    // ---- Logs ----
    private function render_logs(): void {
        global $wpdb;
        $table = $wpdb->prefix . 'market_delivery_logs';

        $per_page = 100;
        $paged = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
        $offset = ($paged - 1) * $per_page;

        $total_logs = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$table}`");
        $logs = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM `{$table}` ORDER BY created_at DESC LIMIT %d OFFSET %d",
            $per_page, $offset
        ));

        echo '<h3>Delivery Logs</h3>';
        echo '<table class="wp-list-table widefat fixed striped">';
        echo '<thead><tr><th>ID</th><th>Order ID</th><th>Buyer UUID</th><th>Prim UUID</th><th>Status</th><th>Message</th><th>Created At</th></tr></thead><tbody>';

        foreach ($logs as $log) {
            echo '<tr>';
            echo '<td>' . intval($log->id) . '</td>';
            echo '<td>' . intval($log->order_id ?: 0) . '</td>';
            echo '<td><code>' . esc_html($log->buyer_uuid) . '</code></td>';
            echo '<td><code>' . esc_html($log->prim_uuid) . '</code></td>';
            echo '<td><span class="status-' . esc_attr($log->status) . '">' . esc_html($log->status) . '</span></td>';
            echo '<td>' . esc_html($log->message) . '</td>';
            echo '<td>' . esc_html($log->created_at) . '</td>';
            echo '</tr>';
        }

        if (empty($logs)) echo '<tr><td colspan="7">No logs yet.</td></tr>';
        echo '</tbody></table>';

        $total_pages = max(1, (int)ceil($total_logs / $per_page));
        if ($total_pages > 1) {
            echo '<div class="tablenav"><div class="tablenav-pages">';
            echo paginate_links([
                'base'      => add_query_arg('paged', '%#%'),
                'format'    => '',
                'prev_text' => __('&laquo;'),
                'next_text' => __('&raquo;'),
                'total'     => $total_pages,
                'current'   => $paged
            ]);
            echo '</div></div>';
        }
    }

    // ---- Cron Import ----
    public function sync_prims(int $batch_size = 500, ?array $target_regions = null): void {
        if (!$this->os_db) {
            error_log('OpenSim Marketplace: OS database not connected for sync_prims');
            return;
        }

        $regions = $this->region_uuids;
        if (is_array($target_regions)) {
            $regions = [];
            foreach ($target_regions as $candidate) {
                $candidate = trim((string) $candidate);
                if ($candidate === '' || !$this->is_valid_uuid($candidate)) {
                    continue;
                }

                foreach ($this->region_uuids as $configured) {
                    if (strcasecmp($configured, $candidate) === 0) {
                        $regions[] = $configured;
                        continue 2;
                    }
                }

                $regions[] = $candidate;
            }
        }

        $regions = array_values(array_unique($regions));
        if (empty($regions)) {
            error_log('OpenSim Marketplace: No region UUIDs configured, sync aborted');
            return;
        }

        $sets = $this->get_ignore_sets();
        $legacy_ignore = $sets['legacy_ignore'] ?? [];
        $uuid_rules    = $sets['uuid_rules'] ?? [];
        $name_exact    = $sets['name_exact'] ?? [];
        $name_contains = $sets['name_contains'] ?? [];

        $offsets_option = get_option('osmp_region_offsets', []);
        $offsets = [];
        if (is_array($offsets_option)) {
            foreach ($offsets_option as $key => $value) {
                $offsets[strtolower((string) $key)] = max(0, (int) $value);
            }
        }

        $should_reschedule = false;

        foreach ($regions as $region_uuid) {
            if (!$this->is_valid_uuid($region_uuid)) {
                error_log('OpenSim Marketplace: Skipping invalid region UUID during sync: ' . $region_uuid);
                continue;
            }

            $offset_key  = strtolower($region_uuid);
            $last_offset = $offsets[$offset_key] ?? 0;
            $limit_clause = sprintf('LIMIT %d, %d', $last_offset, max(1, (int) $batch_size));

            try {
                $sql  = "SELECT UUID, Name FROM prims WHERE RegionUUID = ? {$limit_clause}";
                $stmt = $this->os_db->prepare($sql);
                if (!$stmt) {
                    error_log('OpenSim Marketplace: Failed to prepare sync_prims query for region ' . $region_uuid);
                    continue;
                }

                $stmt->bind_param('s', $region_uuid);
                if (!$stmt->execute()) {
                    error_log('OpenSim Marketplace: Failed to execute sync_prims query for region ' . $region_uuid);
                    $stmt->close();
                    continue;
                }

                $result = $stmt->get_result();
                $count  = 0;

                while ($prim = $result->fetch_assoc()) {
                    $uuid_l = strtolower($prim['UUID']);
                    $name_l = strtolower($prim['Name']);

                    if (in_array($uuid_l, $legacy_ignore, true) || in_array($uuid_l, $uuid_rules, true)) {
                        continue;
                    }
                    if (!empty($name_exact) && in_array($name_l, $name_exact, true)) {
                        continue;
                    }
                    if (!empty($name_contains)) {
                        $skip = false;
                        foreach ($name_contains as $needle) {
                            if ($needle !== '' && strpos($name_l, $needle) !== false) {
                                $skip = true;
                                break;
                            }
                        }
                        if ($skip) {
                            continue;
                        }
                    }

                    $existing = get_posts([
                        'post_type'      => 'opensim_item',
                        'meta_key'       => '_prim_uuid',
                        'meta_value'     => $prim['UUID'],
                        'posts_per_page' => 1,
                        'post_status'    => 'any',
                    ]);

                    $region_label = $this->get_region_label($region_uuid);

                    if (empty($existing)) {
                        $post_id = wp_insert_post([
                            'post_type'   => 'opensim_item',
                            'post_title'  => sanitize_text_field($prim['Name']),
                            'post_status' => 'publish',
                            'post_content'=> '',
                        ]);
                        if ($post_id && !is_wp_error($post_id)) {
                            update_post_meta($post_id, '_prim_uuid', $prim['UUID']);
                            update_post_meta($post_id, '_region_uuid', $region_uuid);
                            update_post_meta($post_id, '_region_label', $region_label);
                            update_post_meta($post_id, '_price', 100); // editable in post screen
                            update_post_meta($post_id, '_seller_uuid', '');
                            update_post_meta($post_id, '_forsale', 1);
                        }
                    } else {
                        $post_id = $existing[0]->ID ?? null;
                        if ($post_id) {
                            update_post_meta($post_id, '_region_uuid', $region_uuid);
                            update_post_meta($post_id, '_region_label', $region_label);
                        }
                    }

                    $count++;
                }

                $stmt->close();

                if ($count < $batch_size) {
                    $offsets[$offset_key] = 0;
                } else {
                    $offsets[$offset_key] = $last_offset + $batch_size;
                    $should_reschedule = true;
                }

                error_log(sprintf(
                    'OpenSim Marketplace: sync_prims processed %d items for region %s (offset %d)',
                    $count,
                    $region_uuid,
                    $last_offset
                ));
            } catch (Throwable $e) {
                error_log('OpenSim Marketplace sync_prims error (region ' . $region_uuid . '): ' . $e->getMessage());
            }
        }

        update_option('osmp_region_offsets', $offsets);

        if ($should_reschedule) {
            wp_schedule_single_event(time() + 1, 'osmp_cron_import');
        }
    }

    private function remove_duplicate_items(): array {
        global $wpdb;

        $result = [
            'groups'     => 0,
            'removed'    => 0,
            'errors'     => 0,
            'prim_uuids' => [],
        ];

        try {
            $query = $wpdb->prepare(
                "SELECT pm.meta_value AS prim_uuid,
                        GROUP_CONCAT(pm.post_id ORDER BY p.post_date ASC SEPARATOR ',') AS post_ids,
                        COUNT(*) AS duplicates
                   FROM {$wpdb->postmeta} pm
                   INNER JOIN {$wpdb->posts} p ON p.ID = pm.post_id
                  WHERE pm.meta_key = %s
                    AND p.post_type = %s
                    AND p.post_status <> 'trash'
                    AND pm.meta_value <> ''
               GROUP BY pm.meta_value
                 HAVING COUNT(*) > 1",
                '_prim_uuid',
                'opensim_item'
            );

            $rows = (array) $wpdb->get_results($query);

            foreach ($rows as $row) {
                $prim_uuid = (string) $row->prim_uuid;
                if (!$this->is_valid_uuid($prim_uuid)) {
                    continue;
                }

                $ids = array_filter(array_map('intval', explode(',', (string) $row->post_ids)));
                if (count($ids) < 2) {
                    continue;
                }

                $result['groups']++;
                $result['prim_uuids'][] = $prim_uuid;

                $keep_id = array_shift($ids);

                foreach ($ids as $post_id) {
                    if ($post_id === $keep_id) {
                        continue;
                    }

                    $trashed = wp_trash_post($post_id);
                    if ($trashed instanceof \WP_Post || $trashed === true) {
                        $result['removed']++;
                    } elseif ($trashed instanceof \WP_Error) {
                        $result['errors']++;
                        error_log('OpenSim Marketplace: Failed to trash duplicate post ' . $post_id . ' for prim ' . $prim_uuid . ': ' . $trashed->get_error_message());
                    } else {
                        $result['errors']++;
                        error_log('OpenSim Marketplace: Failed to trash duplicate post ' . $post_id . ' for prim ' . $prim_uuid);
                    }
                }
            }
        } catch (Throwable $e) {
            error_log('OpenSim Marketplace: Error removing duplicate items: ' . $e->getMessage());
        }

        return $result;
    }

    // ---- Avatar Login ----
    public function handle_avatar_login(): void {
        if (!isset($_POST['_wpnonce']) || !wp_verify_nonce(sanitize_text_field((string) $_POST['_wpnonce']), 'osmp_avatar_login')) {
            wp_send_json_error('Security check failed');
        }

        $uuid = isset($_POST['avatar_uuid']) ? sanitize_text_field((string) $_POST['avatar_uuid']) : '';
        $uuid = trim($uuid);

        if ($uuid === '' || !$this->is_valid_uuid($uuid)) {
            wp_send_json_error('Invalid avatar UUID');
        }

        $avatar_name = $this->get_avatar_name($uuid);

        $this->issue_avatar_session($uuid);
        $balance = $this->get_user_balance($uuid);
        $image = $this->get_texture_proxy_url($uuid);

        $display = $avatar_name ?: $uuid;
        $payload = [
            'uuid'    => $uuid,
            'name'    => $display,
            'display' => $display,
            'balance' => $balance,
        ];

        if ($avatar_name !== null) {
            $payload['avatar_name'] = $avatar_name;
        }
        if ($image) {
            $payload['image'] = $image;
        }
        if ($avatar_name === null && $this->os_db) {
            $payload['warning'] = 'Avatar record not found; proceeding with UUID only.';
        }

        wp_send_json_success($payload);
    }

    public function handle_avatar_logout(): void {
        if (!isset($_POST['_wpnonce']) || !wp_verify_nonce(sanitize_text_field((string) $_POST['_wpnonce']), 'osmp_avatar_login')) {
            wp_send_json_error('Security check failed');
        }

        $this->clear_avatar_session();
        wp_send_json_success(['message' => 'Logged out']);
    }

    // ---- Purchase Handling ----
    public function handle_purchase(): void {
        if (!isset($_POST['_wpnonce']) || !wp_verify_nonce(sanitize_text_field((string) $_POST['_wpnonce']), 'osmp_purchase')) { wp_send_json_error('Security check failed'); }
        if (!$this->money_db) { wp_send_json_error('Service temporarily unavailable'); }

        $buyer_context = $this->resolve_buyer_context();
        $buyer_uuid = $buyer_context['uuid'] ?? '';
        if (empty($buyer_uuid) || !$this->is_valid_uuid($buyer_uuid)) { wp_send_json_error('Authentication required'); }

        $item_id = isset($_POST['item_id']) ? intval($_POST['item_id']) : 0;
        if ($item_id <= 0) { wp_send_json_error('Invalid item ID'); }

        $item = get_post($item_id);
        if (!$item || $item->post_type !== 'opensim_item') { wp_send_json_error('Item not found'); }

        $price = floatval(get_post_meta($item_id, '_price', true));
        $seller_uuid = get_post_meta($item_id, '_seller_uuid', true);
        $prim_uuid = get_post_meta($item_id, '_prim_uuid', true);
        $region_uuid = get_post_meta($item_id, '_region_uuid', true);
        $item_name = is_object($item) ? (string) $item->post_title : '';

        $buyer_display = $buyer_context['display'] ?? '';
        if ($buyer_display === '' && !empty($buyer_context['avatar_name'])) {
            $buyer_display = (string) $buyer_context['avatar_name'];
        }
        if ($buyer_display === '') {
            $buyer_display = $this->resolve_avatar_display($buyer_uuid);
        }

        if ($price < 0) { wp_send_json_error('Invalid price'); }
        if (!$this->is_valid_uuid($prim_uuid)) { wp_send_json_error('Invalid prim UUID'); }

        try {
            $this->money_db->begin_transaction();

            $stmt = $this->money_db->prepare("SELECT balance FROM balances WHERE user = ? FOR UPDATE");
            if (!$stmt) throw new Exception('Failed to prepare balance query');
            $stmt->bind_param('s', $buyer_uuid);
            if (!$stmt->execute()) throw new Exception('Failed to execute balance query');
            $stmt->bind_result($buyer_balance);
            if (!$stmt->fetch()) { $stmt->close(); throw new Exception('Buyer balance not found'); }
            $stmt->close();

            if ($buyer_balance < $price) { $this->money_db->rollback(); wp_send_json_error('Insufficient funds'); }

            $stmt = $this->money_db->prepare("UPDATE balances SET balance = balance - ? WHERE user = ?");
            if (!$stmt) throw new Exception('Failed to prepare buyer debit query');
            $stmt->bind_param('ds', $price, $buyer_uuid);
            if (!$stmt->execute()) throw new Exception('Failed to debit buyer');
            $stmt->close();

            if (!empty($seller_uuid) && $this->is_valid_uuid($seller_uuid)) {
                $stmt = $this->money_db->prepare("UPDATE balances SET balance = balance + ? WHERE user = ?");
                if ($stmt) { $stmt->bind_param('ds', $price, $seller_uuid); $stmt->execute(); $stmt->close(); }
            }

            $orders_table = 'wp_market_orders';
            $stmt = $this->money_db->prepare("INSERT INTO `{$orders_table}` (buyer_uuid, seller_uuid, prim_uuid, price, status, created_at) VALUES (?, ?, ?, ?, 'pending', NOW())");
            if (!$stmt) throw new Exception('Failed to prepare order insert query');
            $stmt->bind_param('sssd', $buyer_uuid, $seller_uuid, $prim_uuid, $price);
            if (!$stmt->execute()) throw new Exception('Failed to insert order');
            $order_id = $stmt->insert_id;
            $stmt->close();

            $this->money_db->commit();

            $delivery_result = $this->deliver_item($prim_uuid, $buyer_uuid, $item_name, $buyer_display, $region_uuid);
            $this->log_delivery($order_id, $prim_uuid, $buyer_uuid, $delivery_result);

            wp_send_json_success([
                'status'   => $delivery_result['status'],
                'message'  => $delivery_result['message'],
                'order_id' => $order_id
            ]);
        } catch (Throwable $e) {
            if ($this->money_db) $this->money_db->rollback();
            error_log('OpenSim Marketplace purchase error: ' . $e->getMessage());
            wp_send_json_error('Purchase failed: ' . $e->getMessage());
        }
    }

    private function deliver_item(string $prim_uuid, string $buyer_uuid, string $item_name = '', string $buyer_name = '', ?string $region_uuid = null): array {
        try {
            if (!$this->is_valid_uuid($prim_uuid)) {
                throw new Exception('Invalid prim UUID for delivery');
            }
            if (!$this->is_valid_uuid($buyer_uuid)) {
                throw new Exception('Invalid buyer UUID for delivery');
            }
            $delivery_api_base = $this->get_region_delivery_api_url($region_uuid);
            if ($delivery_api_base === '') {
                throw new Exception('Delivery API URL is not configured');
            }

            $query = [
                'oid' => $prim_uuid,
                'uid' => $buyer_uuid,
            ];

            if ($this->delivery_api_password !== '') {
                $query['pass'] = $this->delivery_api_password;
            }
            if ($item_name !== '') {
                $query['name'] = $item_name;
            }
            if ($region_uuid && $this->is_valid_uuid($region_uuid)) {
                $query['region'] = $region_uuid;
            }

            $request_url = add_query_arg(array_map(static fn($value) => is_scalar($value) ? (string) $value : '', $query), $delivery_api_base);

            $response = wp_remote_get($request_url, [
                'timeout' => 30,
                'headers' => [
                    'Accept'     => 'application/json, text/plain;q=0.9',
                    'User-Agent' => 'OpenSimMarketplace/2.0 (+WordPress)'
                ],
            ]);

            if (is_wp_error($response)) {
                throw new Exception('Delivery request failed: ' . $response->get_error_message());
            }

            $status_code = (int) wp_remote_retrieve_response_code($response);
            $body        = trim((string) wp_remote_retrieve_body($response));

            if ($status_code >= 200 && $status_code < 300) {
                $message = $this->parse_delivery_message($body, $item_name, $prim_uuid, $buyer_name, $buyer_uuid);
                return [
                    'status'  => 'delivered',
                    'message' => $message,
                ];
            }

            $error_message = $this->parse_delivery_error($body, $status_code);
            return ['status' => 'failed', 'message' => $error_message];
        } catch (Throwable $e) {
            error_log('OpenSim Marketplace delivery error: ' . $e->getMessage());
            return ['status' => 'failed', 'message' => 'Delivery failed: ' . $e->getMessage()];
        }
    }

    private function parse_delivery_message(string $body, string $item_name, string $prim_uuid, string $buyer_name, string $buyer_uuid): string {
        $default_item  = $item_name !== '' ? $item_name : $prim_uuid;
        $default_buyer = $buyer_name !== '' ? $buyer_name : $buyer_uuid;
        $default_message = sprintf("Sent '%s' to %s (%s).", $default_item, $default_buyer, $buyer_uuid);

        if ($body === '') {
            return $default_message;
        }

        $decoded = json_decode($body, true);
        if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
            if (!empty($decoded['message'])) {
                return (string) $decoded['message'];
            }
            if (!empty($decoded['status_message'])) {
                return (string) $decoded['status_message'];
            }
            if (!empty($decoded['status'])) {
                return (string) $decoded['status'];
            }
        }

        return $body;
    }

    private function parse_delivery_error(string $body, int $status_code): string {
        $prefix = 'Delivery failed';

        if ($body !== '') {
            $decoded = json_decode($body, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                if (!empty($decoded['message'])) {
                    return $prefix . ': ' . (string) $decoded['message'];
                }
                if (!empty($decoded['error'])) {
                    return $prefix . ': ' . (string) $decoded['error'];
                }
            }

            return $prefix . ': ' . $body;
        }

        return $prefix . ' with HTTP status ' . $status_code;
    }

    private function resolve_avatar_display(string $avatar_uuid): string {
        if (!$this->is_valid_uuid($avatar_uuid)) {
            return $avatar_uuid;
        }

        if (!function_exists('get_users')) {
            return $avatar_uuid;
        }

        $meta_keys  = $this->get_avatar_meta_keys();
        $meta_query = ['relation' => 'OR'];
        foreach ($meta_keys as $meta_key) {
            $meta_query[] = [
                'key'     => $meta_key,
                'value'   => $avatar_uuid,
                'compare' => '=',
            ];
        }

        if (count($meta_query) === 1) {
            $meta_query[] = [
                'key'     => '_w4os_avatar_uuid',
                'value'   => $avatar_uuid,
                'compare' => '=',
            ];
        }

        $meta_query = apply_filters('osmp_avatar_display_meta_query', $meta_query, $avatar_uuid, $this);

        $users = get_users([
            'meta_query' => $meta_query,
            'number'     => 1,
        ]);

        if (!empty($users)) {
            $user = $users[0];
            if ($user instanceof \WP_User) {
                $name = trim((string) $user->display_name);
                if ($name === '') {
                    $name = trim((string) $user->user_login);
                }
                if ($name !== '') {
                    return $name;
                }
            }
        }

        return $avatar_uuid;
    }

    private function resolve_item_metadata(string $prim_uuid): array {
        $metadata = [
            'name'        => $prim_uuid,
            'region_uuid' => null,
        ];

        if (!$this->is_valid_uuid($prim_uuid)) {
            return $metadata;
        }

        $items = get_posts([
            'post_type'      => 'opensim_item',
            'post_status'    => ['publish', 'draft', 'pending', 'private'],
            'meta_key'       => '_prim_uuid',
            'meta_value'     => $prim_uuid,
            'posts_per_page' => 1,
            'suppress_filters' => false,
        ]);

        if (!empty($items)) {
            $item = $items[0];
            if ($item instanceof \WP_Post) {
                $metadata['name'] = (string) $item->post_title;
                $metadata['region_uuid'] = get_post_meta($item->ID, '_region_uuid', true);
            }
        }

        return $metadata;
    }

    private function log_delivery(int $order_id, string $prim_uuid, string $buyer_uuid, array $result): void {
        if (!$this->money_db) return;
        try {
            $logs_table = 'wp_market_delivery_logs';
            $stmt = $this->money_db->prepare("INSERT INTO `{$logs_table}` (order_id, prim_uuid, buyer_uuid, status, message, created_at) VALUES (?, ?, ?, ?, ?, NOW())");
            if ($stmt) {
                $stmt->bind_param('issss', $order_id, $prim_uuid, $buyer_uuid, $result['status'], $result['message']);
                $stmt->execute(); $stmt->close();

                if ($result['status'] === 'delivered') {
                    $orders_table = 'wp_market_orders';
                    $update_stmt = $this->money_db->prepare("UPDATE `{$orders_table}` SET status = 'delivered' WHERE id = ?");
                    if ($update_stmt) { $update_stmt->bind_param('i', $order_id); $update_stmt->execute(); $update_stmt->close(); }
                }
            }
        } catch (Throwable $e) {
            error_log('OpenSim Marketplace logging error: ' . $e->getMessage());
        }
    }

    private function handle_redelivery(int $order_id): void {
        if (!$this->money_db) { echo '<div class="notice notice-error"><p>Database connection not available</p></div>'; return; }
        try {
            $orders_table = 'wp_market_orders';
            $stmt = $this->money_db->prepare("SELECT * FROM `{$orders_table}` WHERE id = ?");
            if (!$stmt) throw new Exception('Failed to prepare order query');
            $stmt->bind_param('i', $order_id);
            if (!$stmt->execute()) throw new Exception('Failed to execute order query');
            $result = $stmt->get_result();
            $order  = $result->fetch_assoc();
            $stmt->close();

            if (!$order) throw new Exception('Order not found');

            $item_meta = $this->resolve_item_metadata($order['prim_uuid']);
            $buyer_display = $this->resolve_avatar_display($order['buyer_uuid']);
            $delivery_result = $this->deliver_item(
                $order['prim_uuid'],
                $order['buyer_uuid'],
                $item_meta['name'] ?? $order['prim_uuid'],
                $buyer_display,
                $item_meta['region_uuid'] ?? null
            );
            $this->log_delivery($order_id, $order['prim_uuid'], $order['buyer_uuid'], $delivery_result);

            if ($delivery_result['status'] === 'delivered') echo '<div class="notice notice-success"><p>Item redelivered successfully</p></div>';
            else echo '<div class="notice notice-error"><p>Redelivery failed: ' . esc_html($delivery_result['message']) . '</p></div>';
        } catch (Throwable $e) {
            error_log('OpenSim Marketplace redelivery error: ' . $e->getMessage());
            echo '<div class="notice notice-error"><p>Redelivery failed: ' . esc_html($e->getMessage()) . '</p></div>';
        }
    }

    // ---- REST API ----
    public function register_rest_api(): void {
        register_rest_route('osmp/v1', '/items', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_items'],
            'permission_callback' => '__return_true',
            'args' => [
                'page' => ['default' => 1, 'sanitize_callback' => 'absint'],
                'per_page' => ['default' => 20, 'sanitize_callback' => 'absint'],
                'name' => ['sanitize_callback' => 'sanitize_text_field'],
                'region' => ['sanitize_callback' => 'sanitize_text_field'],
            ]
        ]);

        register_rest_route('osmp/v1', '/purchase', [
            'methods'  => 'POST',
            'callback' => [$this, 'api_purchase'],
            'permission_callback' => 'is_user_logged_in'
        ]);
    }

    public function get_items(WP_REST_Request $request): WP_REST_Response {
        global $wpdb;

        $per_page = min(50, max(1, (int)$request->get_param('per_page')));
        $page = max(1, (int)$request->get_param('page'));
        $offset = ($page - 1) * $per_page;

        $where_conditions = ["p.post_type = 'opensim_item'", "p.post_status = 'publish'"];
        $where_values = [];

        if ($name = $request->get_param('name')) {
            $where_conditions[] = "p.post_title LIKE %s";
            $where_values[] = '%' . $wpdb->esc_like($name) . '%';
        }
        if ($region = $request->get_param('region')) {
            $where_conditions[] = "pm2.meta_value = %s";
            $where_values[] = $region;
        }

        $where_clause = 'WHERE ' . implode(' AND ', $where_conditions);

        $query = "SELECT p.ID, p.post_title,
                         pm1.meta_value AS prim_uuid,
                         pm2.meta_value AS region_uuid,
                         COALESCE(pm4.meta_value, pm2.meta_value) AS region_label,
                         pm3.meta_value AS price
                  FROM {$wpdb->prefix}posts p
                  JOIN {$wpdb->prefix}postmeta pm1 ON p.ID = pm1.post_id AND pm1.meta_key = '_prim_uuid'
                  LEFT JOIN {$wpdb->prefix}postmeta pm2 ON p.ID = pm2.post_id AND pm2.meta_key = '_region_uuid'
                  LEFT JOIN {$wpdb->prefix}postmeta pm3 ON p.ID = pm3.post_id AND pm3.meta_key = '_price'
                  LEFT JOIN {$wpdb->prefix}postmeta pm4 ON p.ID = pm4.post_id AND pm4.meta_key = '_region_label'
                  $where_clause
                  ORDER BY p.post_title ASC
                  LIMIT %d OFFSET %d";

        $where_values[] = $per_page;
        $where_values[] = $offset;

        $prepared_query = $wpdb->prepare($query, ...$where_values);
        $items = $wpdb->get_results($prepared_query);

        // Total count for pagination
        $count_query = str_replace(
            "SELECT p.ID, p.post_title, pm1.meta_value AS prim_uuid, pm2.meta_value AS region_uuid, COALESCE(pm4.meta_value, pm2.meta_value) AS region_label, pm3.meta_value AS price",
            "SELECT COUNT(DISTINCT p.ID)",
            $query
        );
        $count_query = str_replace("LIMIT %d OFFSET %d", "", $count_query);
        array_pop($where_values); array_pop($where_values);
        $total_items = (int) $wpdb->get_var($wpdb->prepare($count_query, ...$where_values));

        return new WP_REST_Response([
            'items'       => $items,
            'page'        => $page,
            'per_page'    => $per_page,
            'total'       => $total_items,
            'total_pages' => (int) ceil($total_items / $per_page)
        ]);
    }

    public function api_purchase(WP_REST_Request $request): WP_REST_Response {
        $_POST = $request->get_params();
        $_POST['_wpnonce'] = wp_create_nonce('osmp_purchase');

        ob_start();
        $this->handle_purchase();
        $output = ob_get_clean();

        if (!empty($output)) {
            $response = json_decode($output, true);
            if ($response) return new WP_REST_Response($response);
        }
        return new WP_REST_Response(['error' => 'Purchase processing failed'], 500);
    }

    public static function deactivate(): void {
        wp_clear_scheduled_hook('osmp_cron_import');
    }

    public function __destruct() {
        if ($this->os_db) $this->os_db->close();
        if ($this->money_db) $this->money_db->close();
    }
}

// ---- Initialize Plugin ----
new OpenSimMarketplace();

// ---- Admin CSS (statuses) ----
add_action('admin_head', function() {
    if (isset($_GET['page']) && strpos(sanitize_text_field((string)$_GET['page']), 'osmp_') === 0) {
        echo '<style>
            .status-delivered { color: #00a32a; font-weight: bold; }
            .status-pending { color: #dba617; font-weight: bold; }
            .status-failed { color: #d63638; font-weight: bold; }
            .wp-list-table code { background: #f0f0f1; padding: 2px 4px; border-radius: 3px; }
        </style>';
    }
});

// No closing PHP tag to avoid accidental output
