<?php
require_once 'configs.php';
/**
 * Description of newPHPClass
 *
 * @author pedro
 */
class DB {
    private $pdo;
    
    public function __construct() {
        $pdo = new PDO('firebird:dbname=localhost:C:\\Users\pedro\Documents\JSalgado\Backoffice IPATIMUP\APP.FDB;host=localhost','SYSDBA','masterkey');
        $pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
        $this->pdo = $pdo;
    }
    
    public function query($query,$params=array()){
        $statement = $this->pdo->prepare($query);
        $statement->execute($params);
        
        if(explode(' ',$query)[0]=='SELECT'){
            $data = $statement->fetchAll();
            return $data;
        }
    }
}
