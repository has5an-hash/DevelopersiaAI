<?php
/**
 * Plugin Name: Developersia AI Connector
 * Plugin URI: https://developersia.ir/
 * Description: Securely connects this WordPress site to the Developersia AI platform.
 * Version: 0.1.0
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
    const VERSION = '0.1.0';
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

        update_option(self::OPTION, array(
            'server_url' => untrailingslashit($server_url),
            'site_token' => sanitize_text_field($payload['site_token']),
            'token_hash' => hash('sha256', sanitize_text_field($payload['site_token'])),
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
        delete_option(self::OPTION);
        $this->set_notice('Developersia AI has been disconnected from this site.', 'success');
        $this->redirect_settings();
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

        $user_id = isset($settings['user_id']) ? absint($settings['user_id']) : 0;
        $user = $user_id ? get_user_by('id', $user_id) : false;
        if (!$user || !user_can($user, 'edit_posts')) {
            return new WP_Error('developersia_user_unavailable', 'The WordPress account linked to Developersia is unavailable or lacks permission.', array('status' => 403));
        }

        wp_set_current_user($user_id);
        return true;
    }

    public function status() {
        if (!current_user_can('edit_posts')) {
            return new WP_Error('developersia_forbidden', 'The linked WordPress user cannot edit posts.', array('status' => 403));
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
        if (!current_user_can('edit_posts')) {
            return new WP_Error('developersia_forbidden', 'The linked WordPress user cannot edit posts.', array('status' => 403));
        }
        $page = max(1, absint($request->get_param('page')));
        $per_page = min(20, max(1, absint($request->get_param('per_page'))));
        $search = sanitize_text_field((string) $request->get_param('search'));
        $query = new WP_Query(array(
            'post_type' => array('post', 'page'),
            'post_status' => array('publish', 'draft', 'pending', 'private'),
            'posts_per_page' => $per_page,
            'paged' => $page,
            's' => $search,
            'orderby' => 'modified',
            'order' => 'DESC',
        ));
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

    public function create_draft($request) {
        if (!current_user_can('edit_posts')) {
            return new WP_Error('developersia_forbidden', 'You cannot create drafts.', array('status' => 403));
        }
        $title = sanitize_text_field((string) $request->get_param('title'));
        $content = wp_kses_post((string) $request->get_param('content'));
        $excerpt = sanitize_textarea_field((string) $request->get_param('excerpt'));
        $post_type = sanitize_key((string) $request->get_param('post_type'));
        if (!$title || !$content || !in_array($post_type, array('post', 'page'), true)) {
            return new WP_Error('developersia_invalid_post', 'A title, content and valid post type are required.', array('status' => 400));
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
