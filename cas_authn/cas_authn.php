<?php

// ini_set('display_errors', E_ALL);

/**
 * CAS Authentication This plugin augments the RoundCube login page with the
 * ability to authenticate to a CAS server.
 *
 * @version 0.1
 * @author IFSC
 */
class cas_authn extends rcube_plugin
{

    private $cas_inited;

    private $phpCAS;

    /**
     * Initialize plugin
     */
    function init ()
    {
        // initialize plugin fields
        $this->cas_inited = false;

        // load plugin configuration
        $this->load_config();

        // add application hooks

        $this->add_hook('startup', array(
                $this,
                'startup'
        ));

        $this->add_hook('template_object_loginform', array(
                $this,
                'add_cas_login_html'
        ));

        $this->add_hook('storage_connect', array(
                $this,
                'impersonate'
        ));
        $this->add_hook('smtp_connect', array($this, 'smtp_connect'));
        $this->add_hook('managesieve_connect', array(
                $this,
                'impersonate'
        ));
        $this->add_hook('authenticate', array(
                $this,
                'login'
        ));
        $this->add_hook('sieverules_connect', array(
                $this,
                'impersonate_sieve'
        ));
        $this->add_hook('addressbooks_list', array(
                $this,
                'addressBook'
        ));
    }

    function addressBook($data)
    {
        //print_r($data);die;
    }

    function login ($data)
    {
        // find the seperator character
        $rcmail = rcmail::get_instance();
        $this->load_config();

        $seperator = $rcmail->config->get('dovecot_impersonate_seperator', '*');

        if (strpos($data['user'], $seperator)) {
            $arr = explode($seperator, $data['user']);
            if (count($arr) == 2) {
                $data['user'] = $arr[0];
                $_SESSION['plugin.dovecot_impersonate_master'] = $seperator . $arr[1];
            }
        }

        return ($data);
    }

    function impersonate ($data)
    {
        if (isset($_SESSION['plugin.dovecot_impersonate_master'])) {
            $data['user'] = $data['user'] . $_SESSION['plugin.dovecot_impersonate_master'];
        }

        return ($data);
    }

    function smtp_connect($args) {
        // retrieve configuration
        $cfg = rcmail::get_instance()->config->all();
        
        // RoundCube is acting as CAS proxy and performing SMTP authn
       // if ($cfg['cas_proxy']) {
            // initialize CAS client
            $this->cas_init();

            // retrieve a new proxy ticket and use it as SMTP password
            // Without forceAuthentication() then retrievePT() fails.
            if ($this->phpCAS->isSessionAuthenticated()) {
                $this->phpCAS->forceAuthentication();

                $user = $this->phpCAS->getUser();

                if (!strpos($user, '@hagiang.gov.vn')) {
                    $user = $user . '@hagiang.gov.vn*dovecot_master2';
                } else {
                    $user = $user . '*dovecot_master2';
                }

                $args['smtp_user'] = $user;
                $args['smtp_pass'] = $cfg['cas_imap_password'];
            }
       // }
            
        return $args;
    }

    function impersonate_sieve ($data)
    {
        if (isset($_SESSION['plugin.dovecot_impersonate_master'])) {
            $data['username'] = $data['username'] . $_SESSION['plugin.dovecot_impersonate_master'];
        }
        return ($data);
    }

    /**
     * Handle plugin-specific actions These actions are handled at the startup
     * hook rather than registered as custom actions because the user session
     * does not necessarily exist when these actions need to be handled.
     *
     * @param array $args
     *            arguments from rcmail
     * @return array modified arguments
     */
    function startup ($args)
    {
        if ($args['task'] == 'logout') {
            // initialize CAS client
            $this->cas_init();

            // Redirect to CAS logout action if user is logged in to CAS.
            // Also, do the normal Roundcube logout actions.
            if ($this->phpCAS->isSessionAuthenticated()) {
                $RCMAIL = rcmail::get_instance();
                $RCMAIL->logout_actions();
                $RCMAIL->kill_session();
                $RCMAIL->plugins->exec_hook('logout_after', $userdata);
                $this->phpCAS->logout();
                exit();
            }
        } else if ($args['action'] == 'caslogin') {

            // initialize CAS client
            $this->cas_init();

            // Look for _url GET variable and update FixedServiceURL if present
            // to enable deep linking.
            $query = array();
            if ($url = rcube_utils::get_input_value('_url', rcube_utils::INPUT_GET)) {
                $this->phpCAS->setFixedServiceURL($this->generate_url(array(
                        'action' => 'caslogin',
                        '_url' => $url
                )));
                parse_str($url, $query);
            }

            // Force the user to log in to CAS, using a redirect if necessary.
            $this->phpCAS->forceAuthentication();

            // If control reaches this point, user is authenticated to CAS.
            $user = $this->phpCAS->getUser();

            if (!strpos($user, '@hagiang.gov.vn')) {
                $user = $user . '@hagiang.gov.vn*dovecot_master2';
            } else {
                $user = $user . '*dovecot_master2';
            }

            $RCMAIL = rcmail::get_instance();
            $cfg = rcmail::get_instance()->config->all();

            $pass = $cfg['cas_imap_password'];

            // Do Roundcube login actions

            $auth = $RCMAIL->plugins->exec_hook('authenticate',
                    array(
                            'host' => $RCMAIL->autoselect_host(),
                            'user' => trim($user),
                            'pass' => $pass,
                            'cookiecheck' => true,
                            'valid' => true
                    ));

            // Login
            if ($auth['valid'] && !$auth['abort'] && $RCMAIL->login($auth['user'], $auth['pass'], $auth['host'], $auth['cookiecheck'])) {
                $RCMAIL->session->remove('temp');
                // We don't change the session id which is the CAS login ST.
                $RCMAIL->session->set_auth_cookie();

                // log successful login
                $RCMAIL->log_login();
            } else {
                if (!$auth['valid']) {
                    $error_code = RCMAIL::ERROR_INVALID_REQUEST;
                } else {
                    $error_code = $auth['error'] ? $auth['error'] : $RCMAIL->login_error();
                }

                $error_labels = array(
                        RCMAIL::ERROR_STORAGE => 'storageerror',
                        RCMAIL::ERROR_COOKIES_DISABLED => 'cookiesdisabled',
                        RCMAIL::ERROR_INVALID_REQUEST => 'invalidrequest',
                        RCMAIL::ERROR_INVALID_HOST => 'invalidhost'
                );

                $error_message = $error_labels[$error_code] ? $error_labels[$error_code] : 'loginfailed';

                // log failed login
                $RCMAIL->log_login($auth['user'], true, $error_code);

                $RCMAIL->plugins->exec_hook('login_failed',
                        array(
                                'code' => $error_code,
                                'host' => $auth['host'],
                                'user' => $auth['user']
                        ));

                $RCMAIL->kill_session();
            }

            // allow plugins to control the redirect url after login success
            $redir = $RCMAIL->plugins->exec_hook('login_after', $query + array(
                    '_task' => 'mail'
            ));
            unset($redir['abort'], $redir['_err']);

            // send redirect, otherwise control will reach the mail display and
            // fail because the
            // IMAP session was already started by $RCMAIL->login()
            //global $OUTPUT;
            //$OUTPUT->redirect($redir);
            $RCMAIL->output->redirect($redir);
        }

        return $args;
    }

    /**
     * Prepend link to CAS login above the Roundcube login form if the user
     * would like to login with CAS.
     */
    function add_cas_login_html ($args)
    {
        $RCMAIL = rcmail::get_instance();
        $this->add_texts('localization');
        // retrieve configuration
        $cfg = rcmail::get_instance()->config->all();

        // Force CAS authn?
        if ($cfg["cas_force"]) {
            //global $OUTPUT;
            $RCMAIL->output->redirect(array(
                    'action' => 'caslogin'
            ));
        }

        $caslogin_content = html::div(array(
                'style' => 'border-bottom: 1px dotted #000; text-align: center; padding-bottom: 1em; margin-bottom: 1em;'
        ),
                html::a(
                        array(
                                'href' => $this->generate_url(array(
                                        'action' => 'caslogin'
                                )),
                                'title' => $this->gettext('casloginbutton')
                        ), $this->gettext('casloginbutton')));
        $args['content'] = $caslogin_content . $args['content'];
        return $args;
    }

    /**
     * Initialize CAS client
     */
    private function cas_init ()
    {
        // include phpCAS
        require_once 'vendor/apereo/phpcas/CAS.php';

        $this->phpCAS = new phpCAS();

        if (!$this->cas_inited) {
            $RCMAIL = rcmail::get_instance();

            $old_session = $_SESSION;

            $cfg = rcmail::get_instance()->config->all();

            // Uncomment the following line for phpCAS call tracing, helpful for
            // debugging.
            if ($cfg['cas_debug']) {
                $this->phpCAS->setDebug($cfg['cas_debug_file']);
            }

            // initialize CAS client
            if ($cfg['cas_proxy']) {
                // Manage the session only the first time
                $this->phpCAS->proxy(CAS_VERSION_3_0, $cfg['cas_hostname'], $cfg['cas_port'], $cfg['cas_uri'], !isset($_SESSION['session_inited']));

                // set URL for PGT callback
                $this->phpCAS->setFixedCallbackURL($this->generate_url(array(
                        'action' => 'pgtcallback'
                )));

                // set PGT storage
                $this->phpCAS->setPGTStorageFile($cfg['cas_pgt_dir']);
            } else {
                // Manage the session only the first time
                $this->phpCAS->client(CAS_VERSION_3_0, $cfg['cas_hostname'], $cfg['cas_port'], $cfg['cas_uri'], !isset($_SESSION['session_inited']));
            }

            // set SSL validation for the CAS server
            if ($cfg['cas_validation'] == 'self') {
                $this->phpCAS->setCasServerCert($cfg['cas_cert']);

            } else if ($cfg['cas_validation'] == 'ca') {
                $this->phpCAS->setCasServerCACert($cfg['cas_cert']);
            } else {
                $this->phpCAS->setNoCasServerValidation();
            }

	    if ($cfg['proxy_private_key']) {
                $this->phpCAS->setProxyPrivateKey($cfg['proxy_private_key']);
            }

            $this->cas_inited = true;
        }
    }

    /**
     * Handle the logout comming from CAS server (globalLogout)
     *
     * @param
     *            ticket is the ST name given by CAS for the user when CAS was
     *            requested to authenticate on Roundcube.
     */
    function handleSingleLogout ($ticket)
    {
        $RCMAIL = rcmail::get_instance();
        $RCMAIL->session->destroy($ticket);
    }

    /**
     * Build full URLs to this instance of RoundCube for use with CAS servers
     *
     * @param array $params
     *            url parameters as key-value pairs
     * @return string full Roundcube URL
     */
    private function generate_url ($params)
    {
        $s = ($_SERVER['HTTPS'] == 'on') ? 's' : '';
        $protocol = $this->strleft(strtolower($_SERVER['SERVER_PROTOCOL']), '/') . $s;
        $port = (($_SERVER['SERVER_PORT'] == '80' && $_SERVER['HTTPS'] != 'on') || ($_SERVER['SERVER_PORT'] == '443' && $_SERVER['HTTPS'] == 'on')) ? '' : (':' . $_SERVER['SERVER_PORT']);
        $path = $this->strleft($_SERVER['REQUEST_URI'], '?');
        $parsed_params = '';
        $delm = '?';
        foreach (array_reverse($params) as $key => $val) {
            if (!empty($val)) {
                $parsed_key = $key[0] == '_' ? $key : '_' . $key;
                $parsed_params .= $delm . urlencode($parsed_key) . '=' . urlencode($val);
                $delm = '&';
            }
        }
        $cfg = rcmail::get_instance()->config->all();
        if ($cfg['cas_webmail_server_name']) {
            $serverName = $cfg['cas_webmail_server_name'];
        } else {
            $serverName = $_SERVER['SERVER_NAME'];
        }
        return $protocol . '://' . $serverName . $port . $path . $parsed_params;
    }

    private function strleft ($s1, $s2)
    {
        $length = strpos($s1, $s2);
        if ($length) {
            return substr($s1, 0, $length);
        } else {
            return $s1;
        }
    }
}

?>
