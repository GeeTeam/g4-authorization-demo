<?php 
# ID和KEY需要联系极验获取
$GT_ID = "ID";
$GT_KEY = "KEY";

# 目前提供手机号、ip、三要素、二要素的验证接口
$url = "http://tectapi.geetest.com/queryphonerisk";
# 发送请求，此处是以检测手机黑名单为例子，若需要其他的接口，详见文档。
$phone = "18402951105";
$postdata = array("phone_num"=>md5($phone));

$auth = auth($GT_ID,$GT_KEY);
$result = post_data($url,$auth,$postdata);
echo $result;


function auth($GT_ID,$GT_KEY){
    # 以下是加密部分，可以直接使用，加密方法详见文档。
    $nonce = md5(uniqid()); //1.用户自己生成 timestamp（Unix 时间戳），精确到秒，取整；
    $timestamp = (string)time(); //2.生成随机数nonce(注：最好是32位的) ; 
    $params = array($nonce,$GT_ID,$timestamp);
    sort($params);
    $join_str = implode("",$params); //3.一）将timestamp、nonce、GT_ID 这三个字符串依据字符串首位字符的ASCII码进行升序排列，如果第一个字符相同则比较下一位，依次类推。将三个字符串join成一个字符串；
    $signature = bin2hex(hash_hmac('sha256', $join_str, $GT_KEY, true));
    $arr = array(
        "gt_id"=>$GT_ID,
        "timestamp"=>$timestamp,
        "nonce"=>$nonce,
        "signature"=>$signature
    ); //二）然后用GT_KEY对这个字符串做hamc-sha256 签名，以16进制编码； 

    $string = '';
    foreach ($arr as $key => $value) {
        $string = $string . $key.'='.$value.',';

    }
    $auth=substr($string,0,-1); //将上述的值按照 #{k}=#{v} 并以 ‘,’ join在一起，返回签名认证字符串： 
    return $auth;
}

function post_data($url,$auth,$data){
    $data = http_build_query($data);

    $opts = array(
        'http' => array(
            'method'  => 'POST',
            'header'  => "Content-type: application/x-www-form-urlencoded\r\n" . "Content-Length: " . strlen($data) . "\r\n" . "Authorization: " . $auth . "\r\n",
            'content' => $data,
            'timeout' => 2
        )
    );
    $context = stream_context_create($opts);
    $res    = file_get_contents($url, false, $context);
    return $res;
}





 ?>