<?php
/**
 * Plugin Name: Developersia AI Connector
 * Plugin URI: https://developersia.ir/
 * Description: Securely connects this WordPress site to the Developersia AI platform.
 * Version: 0.1.2
 * Requires at least: 6.5
 * Requires PHP: 8.1
 * Author: Developersia
 * License: Proprietary
 * Text Domain: developersia-ai
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Developersia_AI_Connector {
    const VERSION = '0.1.2';
    const OPTION = 'developersia_ai_connector';

    public function __construct() {
        add_action('admin_menu', array($this, 'admin_menu'));
        add_action('admin_post_developersia_ai_pair', array($this, 'handle_pair'));
        add_action('admin_post_developersia_ai_disconnect', array($this, 'handle_disconnect'));
        add_action('rest_api_init', array($this, 'register_routes'));
        add_action('admin_notices', array($this, 'admin_notice'));
    }

    public function admin_menu() {
        add_options_page(
            'Developersia AI',
            'Developersia AI',
            'manage_options',
            'developersia-ai',
            array($this, 'settings_page')
        );
    }

    public function settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        $settings = get_option(self::OPTION, array());
        $settings = is_array($settings) ? $settings : array();
        $connected = !empty($settings['token_hash']);
        $server_url = isset($settings['server_url']) ? $settings['server_url'] : 'https://api.developersia.ir';

        echo '<div class="wrap"><h1>Developersia AI</h1>';
        echo '<p>Connect this WordPress site to your Developersia AI account. Pairing codes expire after 15 minutes and can only be used once.</p>';

        if ($connected) {
            echo '<div class="notice notice-success inline"><p><strong>Connected.</strong> This site is paired with Developersia AI.</p></div>';
            echo '<p><strong>Developersia API:</strong> ' . esc_html($server_url) . '</p>';
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
            wp_nonce_field('developersia_ai_disconnect');
            echo '<input type="hidden" name="action" value="developersia_ai_disconnect">';
            submit_button('Disconnect this site', 'delete');
            echo '</form>';
        } else {
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
            wp_nonce_field('developersia_ai_pair');
            echo '<input type="hidden" name="action" value="developersia_ai_pair">';
            echo '<table class="form-table"><tbody>';
            echo '<tr><th><label for="developersia_server_url">Developersia API URL</label></th><td><input id="developersia_server_url" name="server_url" type="url" class="regular-text" value="' . esc_attr($server_url) . '" required><p class="description">The HTTPS base URL supplied by Developersia.</p></td></tr>';
            echo '<tr><th><label for="developersia_pairing_code">One-time pairing code</label></th><td><input id="developersia_pairing_code" name="pairing_code" type="text" class="regular-text" autocomplete="off" required></td></tr>';
            echo '</tbody></table>';
            submit_button('Connect to Developersia AI');
            echo '</form>';
        }

        echo '<hr><p><strong>Privacy:</strong> The connector sends WordPress site details and content only when an authorized Developersia AI tool is called. It does not publish new content automatically.</p>';
        echo '</div>';
    }

    public function handle_pair() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to connect this site.', 'developersia-ai'), 403);
        }
        check_admin_referer('developersia_ai_pair');

        $server_url = isset($_POST['server_url']) ? esc_url_raw(trim(wp_unslash($_POST['server_url']))) : '';
        $code = isset($_POST['pairing_code']) ? sanitize_text_field(wp_unslash($_POST['pairing_code'])) : '';
        $parsed = wp_parse_url($server_url);

        if (!$server_url || !$parsed || empty($parsed['host']) || empty($parsed['scheme']) || $parsed['scheme'] !== 'https' || !wp_http_validate_url($server_url)) {
            $this->set_notice('Enter a valid HTTPS Developersia API URL.', 'error');
            $this->redirect_settings();
        }
        if (!$code) {
            $this->set_notice('Enter the one-time pairing code from Developersia.', 'error');
            $this->redirect_settings();
        }

        $endpoint = untrailingslashit($server_url) . '/api/v1/sites/pair';
        $response = wp_remote_post($endpoint, array(
            'timeout' => 15,
            'redirection' => 0,
            'sslverify' => true,
            'headers' => array('Content-Type' => 'application/json', 'Accept' => 'application/json'),
            'body' => wp_json_encode(array(
                'code' => $code,
                'site_url' => home_url('/'),
                'site_name' => get_bloginfo('name'),
                'wp_version' => get_bloginfo('version'),
                'plugin_version' => self::VERSION,
            )),
        ));

        if (is_wp_error($response)) {
            $this->set_notice('Could not reach Developersia: ' . $response->get_error_message(), 'error');
            $this->redirect_settings();
        }

        $status = (int) wp_remote_retrieve_response_code($response);
        $payload = json_decode(wp_remote_retrieve_body($response), true);
        if ($status < 200 || $status >= 300 || !is_array($payload) || empty($payload['site_token'])) {
            $message = is_array($payload) && !empty($payload['message']) ? sanitize_text_field($payload['message']) : 'Pairing failed. Check the code and API URL.';
            $this->set_notice($message, 'error');
            $this->redirect_settings();
        }

        $plain_token = sanitize_text_field($payload['site_token']);
        $encrypted_token = $this->encrypt_token($plain_token);
        if (!$encrypted_token) {
            wp_remote_post(untrailingslashit($server_url) . '/api/v1/sites/unpair', array(
                'timeout' => 10,
                'redirection' => 0,
                'sslverify' => true,
                'headers' => array(
                    'Authorization' => 'Bearer ' . $plain_token,
                    'Accept' => 'application/json',
                ),
            ));
            $this->set_notice('Could not securely store the connection token. OpenSSL encryption is required.', 'error');
            $this->redirect_settings();
        }

        update_option(self::OPTION, array(
            'server_url' => untrailingslashit($server_url),
            'site_token_encrypted' => $encrypted_token,
            'token_hash' => hash('sha256', $plain_token),
            'user_id' => get_current_user_id(),
            'connected_at' => time(),
        ), false);

        $this->set_notice('This site is now connected to Developersia AI.', 'success');
        $this->redirect_settings();
    }

    public function handle_disconnect() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to disconnect this site.', 'developersia-ai'), 403);
        }
        check_admin_referer('developersia_ai_disconnect');
        $settings = get_option(self::OPTION, array());
        $settings = is_array($settings) ? $settings : array();
        $remote_disconnected = false;
        $site_token = $this->get_stored_token($settings);

        if (!empty($settings['server_url']) && $site_token !== '') {
            $response = wp_remote_post(untrailingslashit($settings['server_url']) . '/api/v1/sites/unpair', array(
                'timeout' => 10,
                'redirection' => 0,
                'sslverify' => true,
                'headers' => array(
                    'Authorization' => 'Bearer ' . $site_token,
                    'Accept' => 'application/json',
                ),
            ));
            $remote_disconnected = !is_wp_error($response) && (int) wp_remote_retrieve_response_code($response) === 200;
        }

        delete_option(self::OPTION);
        $message = $remote_disconnected
            ? 'Developersia AI has been disconnected from this site and the platform.'
            : 'The local connector was cleared. The platform could not be notified; revoke the site from your Developersia account if it still appears connected.';
        $this->set_notice($message, 'success');
        $this->redirect_settings();
    }

    private function encrypt_token($token) {
        if (!function_exists('openssl_encrypt') || !function_exists('random_bytes')) {
            return '';
        }

        try {
            $iv = random_bytes(12);
            $tag = '';
            $key = hash('sha256', wp_salt('auth') . '|developersia-ai-connector', true);
            $ciphertext = openssl_encrypt($token, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
            if ($ciphertext === false || strlen($tag) !== 16) {
                return '';
            }
            return 'v1.' . base64_encode($iv) . '.' . base64_encode($tag) . '.' . base64_encode($ciphertext);
        } catch (Throwable $error) {
            return '';
        }
    }

    private function get_stored_token($settings) {
        if (!empty($settings['site_token_encrypted']) && function_exists('openssl_decrypt')) {
            $parts = explode('.', (string) $settings['site_token_encrypted'], 4);
            if (count($parts) !== 4 || $parts[0] !== 'v1') {
                return '';
            }

            $iv = base64_decode($parts[1], true);
            $tag = base64_decode($parts[2], true);
            $ciphertext = base64_decode($parts[3], true);
            if (!is_string($iv) || strlen($iv) !== 12 || !is_string($tag) || strlen($tag) !== 16 || !is_string($ciphertext)) {
                return '';
            }

            $key = hash('sha256', wp_salt('auth') . '|developersia-ai-connector', true);
            $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '');
            return is_string($plaintext) ? $plaintext : '';
        }

        // Read the pre-0.1.1 format so existing installations can migrate safely.
        return !empty($settings['site_token']) ? (string) $settings['site_token'] : '';
    }

    private function set_notice($message, $type) {
        set_transient('developersia_ai_notice_' . get_current_user_id(), array(
            'message' => sanitize_text_field($message),
            'type' => $type === 'success' ? 'success' : 'error',
        ), 60);
    }

    public function admin_notice() {
        if (!current_user_can('manage_options')) {
            return;
        }
        $key = 'developersia_ai_notice_' . get_current_user_id();
        $notice = get_transient($key);
        if (!is_array($notice) || empty($notice['message'])) {
            return;
        }
        delete_transient($key);
        $class = $notice['type'] === 'success' ? 'notice-success' : 'notice-error';
        echo '<div class="notice ' . esc_attr($class) . ' is-dismissible"><p>' . esc_html($notice['message']) . '</p></div>';
    }

    private function redirect_settings() {
        wp_safe_redirect(admin_url('options-general.php?page=developersia-ai'));
        exit;
    }

    public function register_routes() {
        register_rest_route('developersia/v1', '/disconnect', array(
            'methods' => WP_REST_Server::DELETABLE,
            'callback' => array($this, 'disconnect'),
            'permission_callback' => array($this, 'authorize_request'),
        ));

        register_rest_route('developersia/v1', '/status', array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => array($this, 'status'),
            'permission_callback' => array($this, 'authorize_request'),
        ));

        register_rest_route('developersia/v1', '/posts', array(
            array(
                'methods' => WP_REST_Server::READABLE,
                'callback' => array($this, 'list_posts'),
                'permission_callback' => array($this, 'authorize_request'),
                'args' => array(
                    'page' => array('default' => 1, 'sanitize_callback' => 'absint'),
                    'per_page' => array('default' => 10, 'sanitize_callback' => 'absint'),
                    'search' => array('sanitize_callback' => 'sanitize_text_field'),
                ),
            ),
            array(
                'methods' => WP_REST_Server::CREATABLE,
                'callback' => array($this, 'create_draft'),
                'permission_callback' => array($this, 'authorize_request'),
            ),
        ));

        register_rest_route('developersia/v1', '/seo-audit/(?P<id>\d+)', array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => array($this, 'seo_audit'),
            'permission_callback' => array($this, 'authorize_request'),
        ));

        register_rest_route('developersia/v1', '/posts/(?P<id>\d+)', array(
            array(
                'methods' => WP_REST_Server::READABLE,
                'callback' => array($this, 'read_post'),
                'permission_callback' => array($this, 'authorize_request'),
            ),
            array(
                'methods' => WP_REST_Server::CREATABLE,
                'callback' => array($this, 'update_draft'),
                'permission_callback' => array($this, 'authorize_request'),
            ),
        ));
    }

    public function authorize_request($request) {
        $settings = get_option(self::OPTION, array());
        $settings = is_array($settings) ? $settings : array();
        $stored_hash = isset($settings['token_hash']) ? (string) $settings['token_hash'] : '';
        $header = (string) $request->get_header('authorization');

        if (!$header && isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $header = sanitize_text_field(wp_unslash($_SERVER['HTTP_AUTHORIZATION']));
        }
        if (!$stored_hash || !preg_match('/^Bearer\s+(.+)$/i', $header, $matches)) {
            return new WP_Error('developersia_unauthorized', 'A valid Developersia bearer token is required.', array('status' => 401));
        }

        $provided_hash = hash('sha256', trim($matches[1]));
        if (!hash_equals($stored_hash, $provided_hash)) {
            return new WP_Error('developersia_unauthorized', 'The Developersia token is invalid.', array('status' => 401));
        }

        if (!empty($settings['site_token']) && empty($settings['site_token_encrypted'])) {
            $legacy_token = sanitize_text_field($settings['site_token']);
            $encrypted_legacy_token = $this->encrypt_token($legacy_token);
            if ($encrypted_legacy_token) {
                $settings['site_token_encrypted'] = $encrypted_legacy_token;
                unset($settings['site_token']);
                update_option(self::OPTION, $settings, false);
            }
        }

        $user_id = isset($settings['user_id']) ? absint($settings['user_id']) : 0;
        $user = $user_id ? get_user_by('id', $user_id) : false;
        if (!$user || (!user_can($user, 'edit_posts') && !user_can($user, 'edit_pages'))) {
            return new WP_Error('developersia_user_unavailable', 'The WordPress account linked to Developersia is unavailable or lacks permission.', array('status' => 403));
        }

        wp_set_current_user($user_id);
        return true;
    }

    public function disconnect() {
        if (!current_user_can('manage_options')) {
            return new WP_Error('developersia_forbidden', 'Only a site administrator can disconnect the connector.', array('status' => 403));
        }
        delete_option(self::OPTION);
        return rest_ensure_response(array('disconnected' => true));
    }

    public function status() {
        if (!current_user_can('edit_posts') && !current_user_can('edit_pages')) {
            return new WP_Error('developersia_forbidden', 'The linked WordPress user cannot edit posts or pages.', array('status' => 403));
        }
        return rest_ensure_response(array(
            'site_name' => get_bloginfo('name'),
            'site_url' => home_url('/'),
            'wp_version' => get_bloginfo('version'),
            'php_version' => PHP_VERSION,
            'plugin_version' => self::VERSION,
            'connected_user' => wp_get_current_user()->user_login,
            'status' => 'connected',
        ));
    }

    public function list_posts($request) {
        if (!current_user_can('edit_posts') && !current_user_can('edit_pages')) {
            return new WP_Error('developersia_forbidden', 'The linked WordPress user cannot edit posts or pages.', array('status' => 403));
        }
        $page = max(1, absint($request->get_param('page')));
        $per_page = min(20, max(1, absint($request->get_param('per_page'))));
        $search = sanitize_text_field((string) $request->get_param('search'));
        $query_args = array(
            'post_type' => array('post', 'page'),
            'post_status' => array('publish', 'draft', 'pending', 'private'),
            'posts_per_page' => $per_page,
            'paged' => $page,
            's' => $search,
            'orderby' => 'modified',
            'order' => 'DESC',
        );
        if (!current_user_can('edit_others_posts') || !current_user_can('edit_others_pages')) {
            $query_args['author'] = get_current_user_id();
        }
        $query = new WP_Query($query_args);
        $items = array();
        foreach ($query->posts as $post) {
            if (!current_user_can('edit_post', $post->ID)) {
                continue;
            }
            $items[] = $this->format_post($post, false);
        }
        return rest_ensure_response(array(
            'items' => $items,
            'page' => $page,
            'per_page' => $per_page,
            'total' => (int) $query->found_posts,
            'total_pages' => (int) $query->max_num_pages,
        ));
    }

    public function read_post($request) {
        $post = get_post(absint($request['id']));
        if (!$post || !in_array($post->post_type, array('post', 'page'), true)) {
            return new WP_Error('developersia_not_found', 'Post or page not found.', array('status' => 404));
        }
        if (!current_user_can('edit_post', $post->ID)) {
            return new WP_Error('developersia_forbidden', 'You cannot access this post.', array('status' => 403));
        }
        return rest_ensure_response($this->format_post($post, true));
    }

    /**
     * Run a lightweight, read-only on-page SEO audit. This is a set of editorial
     * checks, not a substitute for Search Console, crawl data or a specialist SEO suite.
     */
    public function seo_audit($request) {
        $post = get_post(absint($request['id']));
        if (!$post || !in_array($post->post_type, array('post', 'page'), true)) {
            return new WP_Error('developersia_not_found', 'Post or page not found.', array('status' => 404));
        }
        if (!current_user_can('edit_post', $post->ID)) {
            return new WP_Error('developersia_forbidden', 'You cannot audit this post.', array('status' => 403));
        }

        $title = trim(wp_strip_all_tags(get_the_title($post)));
        $excerpt = trim(wp_strip_all_tags((string) $post->post_excerpt));
        $content = (string) $post->post_content;
        $plain_content = trim(wp_strip_all_tags(strip_shortcodes($content)));
        $words = preg_split('/\s+/u', $plain_content, -1, PREG_SPLIT_NO_EMPTY);
        $word_count = is_array($words) ? count($words) : 0;

        $title_length = $this->text_length($title);
        $description_length = $this->text_length($excerpt);
        $h1_count = preg_match_all('/<h1(?:\s|>)/i', $content);
        $h2_count = preg_match_all('/<h2(?:\s|>)/i', $content);
        $h3_count = preg_match_all('/<h3(?:\s|>)/i', $content);
        $link_count = preg_match_all('/<a\b[^>]*\bhref\s*=/i', $content);
        $image_count = preg_match_all('/<img\b/i', $content);
        $missing_alt = $this->count_images_without_alt($content);

        $checks = array();
        if ($title_length < 30 || $title_length > 60) {
            $checks[] = array(
                'id' => 'title_length',
                'severity' => 'notice',
                'message' => 'The title is ' . $title_length . ' characters long.',
                'recommendation' => 'Consider a clear, descriptive title of roughly 30–60 characters. This is a guideline, not a ranking rule.'
            );
        }
        if ($excerpt === '') {
            $checks[] = array(
                'id' => 'description_missing',
                'severity' => 'warning',
                'message' => 'The WordPress excerpt is empty.',
                'recommendation' => 'Add a unique summary that can be reviewed as a candidate meta description. The excerpt is not automatically a meta description unless the active theme or SEO plugin uses it.'
            );
        } elseif ($description_length < 120 || $description_length > 160) {
            $checks[] = array(
                'id' => 'description_length',
                'severity' => 'notice',
                'message' => 'The excerpt contains ' . $description_length . ' characters.',
                'recommendation' => 'Review the summary for clarity and useful coverage. Around 120–160 characters is a practical editorial target, not a guaranteed Google display length.'
            );
        }
        if ($word_count < 300) {
            $checks[] = array(
                'id' => 'content_length',
                'severity' => 'notice',
                'message' => 'The main content contains approximately ' . $word_count . ' words.',
                'recommendation' => 'Check whether the page fully answers its search intent. Do not add filler just to reach a word-count target.'
            );
        }
        if ($word_count >= 250 && (int) $h2_count === 0) {
            $checks[] = array(
                'id' => 'subheadings_missing',
                'severity' => 'notice',
                'message' => 'No H2 subheadings were found in the post content.',
                'recommendation' => 'Use descriptive subheadings where they improve scanning and structure.'
            );
        }
        if ($missing_alt > 0) {
            $checks[] = array(
                'id' => 'images_missing_alt',
                'severity' => 'warning',
                'message' => $missing_alt . ' of ' . (int) $image_count . ' images have an empty or missing alt attribute.',
                'recommendation' => 'Add concise, accurate alternative text to informative images. Use empty alt text for purely decorative images.'
            );
        }
        if ((int) $link_count === 0 && $word_count >= 250) {
            $checks[] = array(
                'id' => 'links_missing',
                'severity' => 'notice',
                'message' => 'No links were found in the post content.',
                'recommendation' => 'Add relevant internal or authoritative external links when they help readers.'
            );
        }

        return rest_ensure_response(array(
            'post_id' => (int) $post->ID,
            'title' => $title,
            'url' => get_permalink($post),
            'status' => $post->post_status,
            'scope_note' => 'Read-only heuristic review of WordPress content. It does not inspect Search Console, rankings, robots directives, canonical tags, schema output or rendered theme metadata.',
            'metrics' => array(
                'title_characters' => $title_length,
                'excerpt_characters' => $description_length,
                'content_words' => $word_count,
                'content_h1_count' => (int) $h1_count,
                'content_h2_count' => (int) $h2_count,
                'content_h3_count' => (int) $h3_count,
                'links' => (int) $link_count,
                'images' => (int) $image_count,
                'images_missing_alt' => (int) $missing_alt,
            ),
            'checks' => $checks,
            'checks_count' => count($checks),
        ));
    }

    private function text_length($value) {
        $matched = preg_match_all('/./us', (string) $value, $characters);
        return $matched === false ? strlen((string) $value) : count($characters[0]);
    }

    private function count_images_without_alt($content) {
        if (class_exists('DOMDocument')) {
            $document = new DOMDocument();
            $previous = libxml_use_internal_errors(true);
            $document->loadHTML('<?xml encoding="utf-8" ?><div>' . $content . '</div>');
            libxml_clear_errors();
            libxml_use_internal_errors($previous);

            $missing = 0;
            foreach ($document->getElementsByTagName('img') as $image) {
                if (trim((string) $image->getAttribute('alt')) === '') {
                    $missing++;
                }
            }
            return $missing;
        }

        preg_match_all('/<img\b[^>]*>/i', $content, $images);
        $missing = 0;
        foreach ($images[0] as $image) {
            if (!preg_match('/\balt\s*=\s*"([^"]*)"/i', $image, $match) || trim($match[1]) === '') {
                if (!preg_match("/\balt\s*=\s*'([^']*)'/i", $image, $single_match) || trim($single_match[1]) === '') {
                    $missing++;
                }
            }
        }
        return $missing;
    }

    public function create_draft($request) {
        $title = sanitize_text_field((string) $request->get_param('title'));
        $content = wp_kses_post((string) $request->get_param('content'));
        $excerpt = sanitize_textarea_field((string) $request->get_param('excerpt'));
        $post_type = sanitize_key((string) $request->get_param('post_type'));
        if (!$title || !$content || !in_array($post_type, array('post', 'page'), true)) {
            return new WP_Error('developersia_invalid_post', 'A title, content and valid post type are required.', array('status' => 400));
        }
        $required_capability = $post_type === 'page' ? 'edit_pages' : 'edit_posts';
        if (!current_user_can($required_capability)) {
            return new WP_Error('developersia_forbidden', 'You do not have permission to create this content type.', array('status' => 403));
        }
        $post_id = wp_insert_post(array(
            'post_title' => $title,
            'post_content' => $content,
            'post_excerpt' => $excerpt,
            'post_type' => $post_type,
            'post_status' => 'draft',
            'post_author' => get_current_user_id(),
        ), true);
        if (is_wp_error($post_id)) {
            return $post_id;
        }
        return new WP_REST_Response(array(
            'message' => 'Draft created. It has not been published.',
            'post' => $this->format_post(get_post($post_id), true),
        ), 201);
    }

    public function update_draft($request) {
        $post = get_post(absint($request['id']));
        if (!$post || !in_array($post->post_type, array('post', 'page'), true)) {
            return new WP_Error('developersia_not_found', 'Post or page not found.', array('status' => 404));
        }
        if (!current_user_can('edit_post', $post->ID)) {
            return new WP_Error('developersia_forbidden', 'You cannot edit this post.', array('status' => 403));
        }
        if (!in_array($post->post_status, array('draft', 'pending'), true)) {
            return new WP_Error('developersia_published_locked', 'Only draft or pending content can be changed by Developersia AI.', array('status' => 409));
        }
        $changes = array('ID' => $post->ID);
        if ($request->has_param('title')) {
            $changes['post_title'] = sanitize_text_field((string) $request->get_param('title'));
        }
        if ($request->has_param('content')) {
            $changes['post_content'] = wp_kses_post((string) $request->get_param('content'));
        }
        if ($request->has_param('excerpt')) {
            $changes['post_excerpt'] = sanitize_textarea_field((string) $request->get_param('excerpt'));
        }
        if (count($changes) === 1) {
            return new WP_Error('developersia_empty_update', 'Provide at least one field to update.', array('status' => 400));
        }
        $updated = wp_update_post($changes, true);
        if (is_wp_error($updated)) {
            return $updated;
        }
        return rest_ensure_response(array(
            'message' => 'Draft updated.',
            'post' => $this->format_post(get_post($updated), true),
        ));
    }

    private function format_post($post, $include_content) {
        $data = array(
            'id' => (int) $post->ID,
            'date' => mysql_to_rfc3339($post->post_date),
            'modified' => mysql_to_rfc3339($post->post_modified),
            'slug' => $post->post_name,
            'status' => $post->post_status,
            'type' => $post->post_type,
            'link' => get_permalink($post),
            'title' => get_the_title($post),
            'excerpt' => wp_strip_all_tags(get_the_excerpt($post)),
        );
        if ($include_content) {
            $data['content'] = $post->post_content;
        }
        return $data;
    }
}

new Developersia_AI_Connector();
