#!/usr/bin/env python3
import argparse
import requests
import re

class Colors:
    RESET = '\033[0m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    ORANGE = '\033[33m'
    BLUE = '\033[34m'
    CYAN = '\033[36m'
    REDHIGHLIGHT ='\033[41m'

# functions that can cause rce
rce = [
        'system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open', 'pcntl_exec'
    ]

# functions to screw with files
File_DIR_Man = [
        'unlink','rmdir','rename','copy','chmod','chown','chgrp','file_put_contents','fopen','fwrite','fclose'
    ]

# functions to execute PHP code
PHP_code_execution = [
        'eval','assert','create_function','call_user_func','call_user_func_array','preg_replace'
    ]

# possible Information Leakage
Info_disclosure = [
        'phpinfo','getenv','getcwd','scandir','glob','opendir','readdir','readfile','file_get_contents'
    ]

# possible SQL injection or remote service exploitation
DB_Exter_Interaction = [
        'mysql_query','mysqli_query','pg_query','sqlite_query','sqlite_exec','odbc_exec'
    ]

# Network and soccet operations
NW_SO = [
        'fsockopen','pfsockopen','socket_create','socket_connect','curl_exec','curl_multi_exec','parse_url'
    ]

# Can in some cases be used to send mail from the server
Mail = [
        'mail','mb_send_mail','imap_mail','imap_open'
    ]

# possible uses in priveledge escalation
PrivEsc = [
        'pcntl_fork','pcntl_wait','pcntl_signal','pcntl_exec','pcntl_getpriority','pcntl_setpriority'
    ]

# Possible system traversal
System_Traversal = [
    'link','symlink','readlink','realpath'
]

# Allow for modification of security settings:
Security = [
    'openssl_encrypt','openssl_decrypt','mcrypt_encrypt','mcrypt_decrypt','hash','md5','sha1','password_hash','ini_set','ini_restore', 'putenv', 'apache_setenv'
]

dangerous_functions = [
        'pcntl_alarm', 'pcntl_fork', 'pcntl_waitpid', 'pcntl_wait', 'pcntl_wifexited',
        'pcntl_wifstopped', 'pcntl_wifsignaled', 'pcntl_wifcontinued', 'pcntl_wexitstatus',
        'pcntl_wtermsig', 'pcntl_wstopsig', 'pcntl_signal', 'pcntl_signal_get_handler',
        'pcntl_signal_dispatch', 'pcntl_get_last_error', 'pcntl_strerror', 'pcntl_sigprocmask',
        'pcntl_sigwaitinfo', 'pcntl_sigtimedwait', 'pcntl_exec', 'pcntl_getpriority',
        'pcntl_setpriority', 'pcntl_async_signals', 'error_log', 'system', 'exec', 'shell_exec',
        'popen', 'proc_open', 'passthru', 'link', 'symlink', 'syslog', 'ld', 'mail'
    ]


def check_phpinfo(phpinfo, lists):
    modules = []
    exploitable_functions = []

    disable_functions_match = re.search(r'disable_functions</td><td class="v">([^<]+)', phpinfo)

    if disable_functions_match:
        disabled_functions = set(disable_functions_match.group(1).split(','))
        exploitable_functions = [func for func in lists if func not in disabled_functions]
    else:
        # If disable_functions is missing, assume all dangerous functions are enabled
        exploitable_functions = lists.copy()
    return exploitable_functions

def modules(phpinfo):
    modules = re.findall(r'(\w+\.ini)', phpinfo)
    if 'mbstring.ini' in modules:
        print("mbstring.ini module is active")
    if 'imap.ini' in modules:
        print("imap.ini module is active")
    if 'libvirt-php.ini' in modules:
        print("{Colors.BLUE}PHP-FPM detected. Consider securing stream_socket_sendto, stream_socket_client, fsockopen.{Colors.RESET}")
    if 'gnupg.ini' in modules:
        print("gnupg.ini module is active")
    if 'imagick.ini' in modules:
        print(f"{Colors.RED}imagick.ini module is active")

def printer(function, color, phpinfo, info):

    exploitable_functions = check_phpinfo(phpinfo, function)
    if exploitable_functions:
        print(f'\n{color}Please consider disabling the following functions:{Colors.RESET}')
        print(', '.join(exploitable_functions))
        print(f'\n{color}These can be used for: {info}{Colors.RESET}')
        return True
    else:
        return False

def main():

    print (Colors.CYAN + """                               
                     M          PHP         
                    PHP        PHP          
                   PHPHP      PHP          
                  PHP PHP    PHP            
                 PHP   PHP  PHP            
                PHP     PHPPHP             
               PHP        PHP              
              PHP        PHPP              
             PHP        PHPPHP             
            PHP        PHP  PHP            
           PHP        PHP    PHP           
          PHP        PHP      PHP          
         PHP        PHP        PHP         
        PHP        PHP          PHP        
       PHP        PHP            PHP       
      PHP        PHP              PHP      
     PHP        PHP                PHP     
    PHP        PHP                  PHP    
   PHP        PHP                    PHP   
  PHPPHPPHPPHPPHPPHPPHPPHPPHPPHPPHPPHPPHP                                           
    """ + "\n\t\t\t" + Colors.BLUE + "author: " + Colors.ORANGE + "Melis_34 @ Melis IT Solutions" + "\n\t\t\t" + Colors.RESET + "inspired by the dfunc-bypasser")





    parser = argparse.ArgumentParser(description=f"PHPinfo Security Analyzer By Melis34")
    parser.add_argument("--url", help="URL of PHPinfo (e.g., https://example.com/phpinfo.php)")
    parser.add_argument("--file", help="Local path to PHPinfo file (e.g., dir/phpinfo)")
    parser.add_argument("-a", help= "check all types", action="store_true")
    parser.add_argument("-rce", help= "check for possible rce", action="store_true")
    parser.add_argument("-phpce", help= "check for possible PHP code execution", action="store_true")
    parser.add_argument("-fd", help= "check for possible file and directory manipulation", action="store_true")
    parser.add_argument("-inf", help="check for possible information disclosure", action="store_true")
    parser.add_argument("-db", help="check for possible interaction with databases and external systems", action="store_true")
    parser.add_argument("-ssrf", help="check for possible Interacting with remote servers, leading to SSRF (Server-Site Request Forgery)", action="store_true")
    parser.add_argument("-mail", help="check for possible ability to send mail", action="store_true")
    parser.add_argument("-privesc", help="check for possible prilege escalation", action="store_true")
    parser.add_argument("-pt", help= "check for possible path traversal", action="store_true")
    parser.add_argument("-sec", help="check for possible security bypass (hashes etc)", action="store_true")
    parser.add_argument("-modules", help="check for modules that can lead to interesting beheavior", action="store_true")

    args = parser.parse_args()

    if not (args.url or args.file):
        parser.print_help()
        return

    phpinfo = ""
    if args.url:
        phpinfo = requests.get(args.url).text
    elif args.file:
        with open(args.file, 'r') as f:
            phpinfo = f.read()

    
    # Critical
    if args.rce or args.a:
        printer(rce, Colors.REDHIGHLIGHT, phpinfo, "Remote Code Execution")

    # Red
    if args.a or args.fd:
        printer(File_DIR_Man, Colors.RED, phpinfo, "File and Directory manipulation")
    if args.a or args.phpce:
        printer(PHP_code_execution, Colors.RED, phpinfo, "PHP code execution")
    if args.a or args.db:
        printer(DB_Exter_Interaction, Colors.RED, phpinfo, "Interaction with Databases and External system interaction")

    # Orange
    if args.a or args.privesc:
        printer(PrivEsc, Colors.ORANGE, phpinfo, "Privilege escalation")
    if args.a or args.pt:
        printer(System_Traversal, Colors.ORANGE, phpinfo, "System Traversal")
    if args.a or args.sec:
        printer(Security, Colors.ORANGE, phpinfo, "Security bypass")


    # Green
    if args.a or args.mail:
        printer(Mail, Colors.GREEN, phpinfo, "Send span or phish users (possibly using the website this php info file was found on)")
    if args.a or args.ssrf:
        printer(NW_SO, Colors.GREEN, phpinfo, "Interacting with remote servers, leading to SSRF (Server-Site Request Forgery)")

    # Blue
    if args.a or args.inf :
        printer(Info_disclosure, Colors.BLUE, phpinfo, "Information Disclosure")
    
    
    

    
    if args.a or args.modules:
        modules(phpinfo)

if __name__ == "__main__":
    main()



