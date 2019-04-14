<?php
namespace Distvan;

use DateTime;
use DateInterval;
use Monolog\Logger;
use SplFileObject;
use Noodlehaus\Config;
use Swift_Message;
use Swift_Mailer;
use Swift_SmtpTransport;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\SwiftMailerHandler;
use Monolog\Formatter\HtmlFormatter;

/**
 * Class CertChecker
 *
 * Check ssl certification expiration of domains and send email notification before x days
 *
 * @author: Istvan Dobrentei
 * @url: https://dobrenteiistvan.hu
 * @link: https://github.com/distvan/certchecker
 */
class CertChecker
{
    const DOMAIN_FILE = 'domains.txt';
    protected $_notificationDays;
    protected $_logger;

    /**
     * CertChecker constructor.
     *
     * If the expiration day is within the current day + days parameter it will send a notification
     * The config parameter is the filename where it reads the settings
     *
     * @param string $config
     */
    public function __construct($config)
    {
        error_reporting(E_ALL);
        $conf = Config::load($config);
        $mailConf = $conf->get('MAIL');
        $appConf = $conf->get('APP');
        $this->_notificationDays = (int)$appConf['days'];
        $this->_logger = new Logger('cert-checking');
        $logFile = dirname(dirname(__FILE__)) . DIRECTORY_SEPARATOR . 'checker.log';
        $this->_logger->pushHandler(new StreamHandler($logFile, Logger::ERROR));

        if(!$appConf['debug'])
        {
            error_reporting(0);
        }

        if(isset($appConf['notification.send']) && $appConf['notification.send'])
        {
            $transporter = new Swift_SmtpTransport($mailConf['smtp.host'],
                $mailConf['smtp.port'], $mailConf['smtp.other']);
            if(isset($mailConf['smtp.user']) && !empty($mailConf['smtp.user']) &&
                isset($mailConf['smtp.password']) && !empty($mailConf['smtp.password'])
            ){
                $transporter->setUsername($mailConf['smtp.user']);
                $transporter->setPassword($mailConf['smtp.password']);
            }
            $mailer = new Swift_Mailer($transporter);
            $message = new Swift_Message('CertChecker Notification');
            $message->setFrom($appConf['notification.from']);
            $emails = explode(",", $appConf['notification.emails']);
            $message->setTo($emails);
            $message->setContentType("text/html");
            $mailerHandler = new SwiftMailerHandler($mailer, $message, Logger::ALERT, false);
            $mailerHandler->setFormatter(new HtmlFormatter());
            $this->_logger->pushHandler($mailerHandler);
        }

        $dir = dirname(dirname(__FILE__));
        $file = new SplFileObject($dir . DIRECTORY_SEPARATOR . self::DOMAIN_FILE);

        while(!$file->eof())
        {
            $domainName = trim($file->fgets());
            $date = $this->getExpirationDate($domainName);
            if($this->isExpirationActual($date))
            {
                $this->_logger->alert('The SSL certification of ' . $domainName
                    . ' will be expired within ' . $this->_notificationDays . ' days');
            }
        }
    }

    /**
     * Get domain expiration date
     * If any error occured send an email with error message
     *
     * @param $domain
     * @return date|int
     */
    protected function getExpirationDate($domain)
    {
        if(empty($domain))
        {
            return 0;
        }

        $get = stream_context_create(
            array(
                "ssl" => array(
                    "capture_peer_cert" => true
                )
            )
        );

        $read = stream_socket_client("ssl://" . $domain . ":443", $errNo, $errStr, 30, STREAM_CLIENT_CONNECT, $get);

        if($read)
        {
            $cert = stream_context_get_params($read);
            $certInfo = openssl_x509_parse($cert['options']['ssl']['peer_certificate']);
        }
        else
        {
            $this->_logger->alert('The SSL certification of ' . $domain . ' can not be checked! ' . $errStr);
        }

        return isset($certInfo['validTo_time_t']) ? date(DATE_RFC2822, $certInfo['validTo_time_t']) : 0;
    }


    /**
     * Checking exiration date and compare to now
     * If it is actual to send notification return true
     *
     * @param $date
     * @return bool
     */
    protected function isExpirationActual($date)
    {
        if($date)
        {
            $certDate = new DateTime($date);
            $now = new DateTime('NOW');
            $dayPeriod = new DateInterval('P' . $this->_notificationDays . 'D');
            $certDate->sub($dayPeriod);

            return $now >= $certDate;
        }

        return false;
    }

}