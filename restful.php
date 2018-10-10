<?php

require_once 'lib/passwordHash.php';
require_once 'DB.php';
$db = new DB();

//POSTS
if  ($_SERVER['REQUEST_METHOD'] == "POST") {
    
    //LOG IN
    if ($_GET['url'] == "auth") {
        $postBody = file_get_contents("php://input");
        $postBody = json_decode($postBody);
        $user = $postBody->username;
        $pass = $postBody->pass;
        //Verificar se utilizador existe
        if ($resp = $db->query("SELECT * FROM cad_util_backoffice WHERE USERNAME=:user", array(':user' => $user))) {
            //verificar se a password e utilizador correspondem
            $found = false;
            $change = false;
                
            foreach ($resp AS $r) {
                if($r['SENHA'] == $pass){
        //        if (passwordHash::check_password($r['SENHA'], $pass)) {
//Se for password defeito aceita mas vai obrigar a alterar
                    if($pass == '123'){ 
                        $change = true;
                    }
                    //regista o login - atualiza a data do ultimo login
                    $db->query("UPDATE cad_util_backoffice SET ULTIMOLOG = '9.10.2018 14:35' WHERE COD_UTIL=:id", array( ':id' => $r['COD_UTIL']));
                    //retorna o token com a indicação change=false (não obriga a alterar a password)
                    $token = generateToken($r, $change);
                    $found =true;
                    echo $token;
                    http_response_code(200);
                }
                if (!$found) {
                    echo null;
                    http_response_code(200);
                }
            }
        } else {
            echo null;
            http_response_code(200);
        }
        
   } 
} else {//Fim dos metodos 
    http_response_code(405);
}

//Functions
//Check token and return user ID or false
function generateToken($resp, $change) {
    //Chave para a encriptação
    $key='klEpFG93';
    
    //Configuração do JWT
    $header = [
        'alg' => 'HS256',
        'typ' => 'JWT'
    ];
    
    $header = json_encode($header);
    $header = base64_encode($header);
    
    //Dados 
    $payload = [
        'iss' => 'IPTIMUP',
        'nome' => $resp['NOME'],
        'tipo' => $resp['TIPO_UTIL'],
        'change' =>$change
    ];
    
    $payload = json_encode($payload);
    $payload = base64_encode($payload);
    
    //Signature
    
    $signature = hash_hmac('sha256', "$header.$payload", $key,true);
    $signature = base64_encode($signature);
   // echo $header.$payload.$signature;
    
    echo "$header.$payload.$signature";
}


