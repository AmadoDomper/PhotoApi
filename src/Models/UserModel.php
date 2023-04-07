<?php

namespace App\Models;

use App\Config\ResponseHttp;
use App\Config\Security;
use App\DB\ConnectionDB;
use App\DB\Sql;

class UserModel extends ConnectionDB {

    //Propiedades de la base de datos
    private static string $idPersona;
    private static string $nombre;
    private static string $apellido;
    private static string $documento;
    private static string $tipoFFVV;
    private static string $sede;
    private static string $correo;
    private static int    $rol;    
    private static string $password;
    private static string $fotoPerfil;
    private static string $fotoDni;
    private static string $IDToken;    

    public function __construct(array $data)
    {
        self::$idPersona   = $data['idPersona'] ?: '';
        self::$nombre   = $data['name'] ?: '';
        self::$apellido   = $data['apellido'] ?: '';
        self::$documento      = $data['documento'] ?: '';
        self::$tipoFFVV      = $data['tipoFFVV'] ?: '';
        self::$sede      = $data['sede'] ?: '';
        self::$correo   = $data['email'] ?: '';
        self::$rol      = $data['rol'] ?: 0;        
        self::$password = $data['password'] ?: ''; 
        self::$fotoPerfil = $data['fotoPerfil'] ?: ''; 
        self::$fotoDni = $data['fotoDni'] ?: ''; 
    }

    /************************Metodos Getter**************************/
    final public static function getPersonaId(){     return self::$idPersona;}
    final public static function getName(){     return self::$nombre;}
    final public static function getApellido(){     return self::$apellido;}
    final public static function getDocumento(){      return self::$documento;}
    final public static function getTipoFFVV(){      return self::$tipoFFVV;}
    final public static function getSede(){      return self::$sede;}
    final public static function getEmail(){    return self::$correo;}
    final public static function getRol(){      return self::$rol;}     
    final public static function getPassword(){ return self::$password;}
    final public static function getFotoPerfil(){ return self::$fotoPerfil;}
    final public static function getFotoDni(){ return self::$fotoDni;}
    final public static function getIDToken(){  return self::$IDToken;}    
    
    /**********************************Metodos Setter***********************************/
    final public static function setPersonaId(string $idPersona) {      self::$idPersona = $idPersona;}
    final public static function setName(string $nombre) {      self::$nombre = $nombre;}
    final public static function setApellido(string $apellido) {      self::$apellido = $apellido;}
    final public static function setDocumento(string $documento){           self::$documento = $documento;}
    final public static function setTipoFFVV(string $tipoFFVV){           self::$tipoFFVV = $tipoFFVV;}
    final public static function setSede(string $sede){           self::$sede = $sede;}
    final public static function setEmail(string $correo){      self::$correo = $correo;}
    final public static function setRol(string $rol){           self::$rol = $rol;}      
    final public static function setPassword(string $password){ self::$password = $password;}
    final public static function setFotoPerfil(string $fotoPerfil){ self::$fotoPerfil = $fotoPerfil;}
    final public static function setFotoDni(string $fotoDni){ self::$fotoDni = $fotoDni;}
    final public static function setIDToken(string $IDToken){   self::$IDToken = $IDToken;}    
    
    /**********************Validar si la contaseña antigua es correcta**************************/
    final public static function validateUserPassword(string $IDToken,string $oldPassword)
    {
        try {
            $con = self::getConnection();
            $query = $con->prepare("SELECT password FROM usuario WHERE IDToken = :IDToken");
            $query->execute([
                ':IDToken' => $IDToken
            ]);

            if ($query->rowCount() == 0) {
                die(json_encode(ResponseHttp::status500()));
            } else {
                $res = $query->fetch(\PDO::FETCH_ASSOC);

                if (Security::validatePassword($oldPassword,$res['password'])){
                    return true;
                } else {
                    return false;
                }               
            }                     
        } catch (\PDOException $e) {
            error_log('UserModel::validateUserPassword -> ' . $e);            
            die(json_encode(ResponseHttp::status500()));
        }
    }

    /*********************************************Login******************************************/
    final public static function login()
    {
        try {
            $con = self::getConnection()->prepare("SELECT * FROM usuario WHERE correo = :correo ");
            $con->execute([
                ':correo' => self::getEmail()
            ]);

            if ($con->rowCount() === 0) {
                return ResponseHttp::status400('El usuario o contraseña son incorrectos');
            } else {
                foreach ($con as $res) {
                    if (Security::validatePassword(self::getPassword() , $res['password'])) {
                            $payload = ['IDToken' => $res['IDToken']];
                            $token = Security::createTokenJwt(Security::secretKey(),$payload);

                            $data = [
                                'name'  => $res['nombre'],
                                'rol'   => $res['rol'],
                                'token' => $token
                            ];
                            return ResponseHttp::status200($data);
                            exit;
                    } else {
                        return ResponseHttp::status400('El usuario o contraseña son incorrectos');
                    }
                }
            }
        } catch (\PDOException $e) {
            error_log("UserModel::Login -> " .$e);
            die(json_encode(ResponseHttp::status500()));           
        }
    }

    /**************************Consultar todos los usuarios***************************/
    final public static function getAll()
    {
        try {
            $con = self::getConnection();
            $query = $con->prepare("SELECT idpersona, nombre, apellido, documento, tipoFFVV, sede  FROM usuario_na");
            $query->execute();
            $rs['data'] = $query->fetchAll(\PDO::FETCH_ASSOC);
            return $rs;
        } catch (\PDOException $e) {
            error_log("UserModel::getAll -> ".$e);
            die(json_encode(ResponseHttp::status500('No se pueden obtener los datos')));
        }
    }

        /**************************Consultar todos los usuarios***************************/
        final public static function getUserPictures()
        {
            try {
                $con = self::getConnection();
                $query = $con->prepare("SELECT UF.documento, UF.fotoPerfil ,UF.fotoDocumento, UF.UltimaActualizacion, U.nombre, U.apellido, U.tipoFFVV, U.sede  
                                        FROM usuario_na_foto UF
                                        INNER JOIN usuario_na U ON U.documento = UF.documento
                                        ORDER BY UF.UltimaActualizacion DESC");
                $query->execute();
                $rs = $query->fetchAll(\PDO::FETCH_ASSOC);
                return $rs;
            } catch (\PDOException $e) {
                error_log("UserModel::getAll -> ".$e);
                die(json_encode(ResponseHttp::status500('No se pueden obtener los datos')));
            }
        }

    /**************************Consultar un usuario por DNI**************************************/
    final public static function getUser()
    {
        try {
            $con = self::getConnection();
            $query = $con->prepare("SELECT idpersona, documento, nombre, apellido,tipoFFVV, sede FROM usuario_na WHERE documento = :documento");
            $query->execute([
                ':documento' => self::getDocumento()
            ]);

            if ($query->rowCount() == 0) {
                return ResponseHttp::status400('El documento ingresado no esta registrado');
            } else {
                    $rs = $query->fetch(\PDO::FETCH_ASSOC);
                    return $rs;
            }          
        } catch (\PDOException $e) {
            error_log("UserModel::getUser -> ".$e);
            die(json_encode(ResponseHttp::status500('No se pueden obtener los datos del usuario')));
        }
    }

    /*******************************************Registrar usuario************************************************/
    final public static function postSave()
    {
        if (Sql::exists("SELECT dni FROM usuario WHERE dni = :dni",":dni",self::getDocumento())) {  
            return ResponseHttp::status400('El DNI ya esta registrado');
        } else if (Sql::exists("SELECT correo FROM usuario WHERE correo = :correo",":correo",self::getEmail())) {
            return ResponseHttp::status400('El Correo ya esta registrado');
        } else {
            self::setIDToken(hash('sha512',self::getDocumento().self::getEmail()));            

            try {
                $con = self::getConnection();
                $query1 = "INSERT INTO usuario (nombre,apellido,dni,correo,rol,password,IDToken) VALUES";
                $query2 = "(:nombre,:apellido,:dni,:correo,:rol,:password,:IDToken)";
                $query = $con->prepare($query1 . $query2);
                $query->execute([
                    ':nombre'  => self::getName(),
                    ':apellido'=> self::getApellido(),
                    ':dni'     => self::getDocumento(),
                    ':correo'  => self::getEmail(),
                    ':rol'     => self::getRol(),                    
                    ':password'=> Security::createPassword(self::getPassword()),
                    ':IDToken' => self::getIDToken()            
                ]);
                if ($query->rowCount() > 0) {
                    return ResponseHttp::status200('Usuario registrado exitosamente');
                } else {
                    return ResponseHttp::status500('No se puede registrar el usuario');
                }
            } catch (\PDOException $e) {
                error_log('UserModel::post -> ' . $e);
                die(json_encode(ResponseHttp::status500()));
            }
        }
    }

    /******************************Actualizar la contraseña de usuario********************************/
    final public static function patchPassword()
    {
        try {
            $con = self::getConnection();
            $query = $con->prepare("UPDATE usuario SET password = :password WHERE IDToken = :IDToken");           
            $query->execute([
                ':password' => Security::createPassword(self::getPassword()),
                ':IDToken'  => self::getIDToken()
            ]);
            if ($query->rowCount() > 0) {
            return ResponseHttp::status200('Contraseña actualizado exitosamente');
            } else {
            return ResponseHttp::status500('Error al actualizar la contraseña del usuario');
            }
        } catch (\PDOException $e) {
            error_log("UserModel::patchPassword -> " . $e);
            die(json_encode(ResponseHttp::status500()));
        }
    }

    /*******************************Eliminar usuario**************************/
    final public static function deleteUser()
    {
        try {
            $con   = self::getConnection();
            $query = $con->prepare("DELETE FROM usuario WHERE IDToken = :IDToken");
            $query->execute([
                ':IDToken' => self::getIDToken()
            ]);

            if ($query->rowCount() > 0) {
                return ResponseHttp::status200('Usuario eliminado exitosamente');
            } else {
                return ResponseHttp::status500('No se puede eliminar el usuario');
            }
        } catch (\PDOException $e) {
            error_log("UserModel::deleteUser -> " . $e);
            die(json_encode(ResponseHttp::status500('No se puede eliminar el usuario')));
        }
    }

    /*******************************************Registrar Fotos************************************************/
    final public static function postSavePictures()
    {
            try {

                $profile = self::saveBase64Picture(self::getFotoPerfil(), '/img/profile/' , self::getDocumento());
                $document = self::saveBase64Picture(self::getFotoDni(), '/img/document/' , self::getDocumento());

                $con = self::getConnection();

                if (Sql::exists("SELECT documento FROM usuario_na_foto WHERE documento = :documento",":documento",self::getDocumento())) {  
                    // $query = $con->prepare("UPDATE usuario_na_foto SET fotoPerfil = :fotoPerfil, fotoDocumento = :fotoDocumento, UltimaActualizacion = CURRENT_TIMESTAMP WHERE documento = :documento");           
                    $query = $con->prepare("UPDATE usuario_na_foto 
                                            SET fotoPerfil = CASE WHEN fotoPerfil = 0 THEN :fotoPerfil ELSE fotoPerfil END, 
                                                fotoDocumento = CASE WHEN fotoDocumento = 0 THEN :fotoDocumento ELSE fotoDocumento END, 
                                                UltimaActualizacion = CURRENT_TIMESTAMP 
                                            WHERE documento = :documento");           
                    $query->execute([
                        ':documento'  => self::getDocumento(),
                        ':fotoPerfil' => $profile > 0 ? 1 : 0,
                        ':fotoDocumento'  => $document > 0 ? 1 : 0
                    ]);
                } else {
                    $query1 = "INSERT INTO usuario_na_foto (documento, fotoPerfil, fotoDocumento, UltimaActualizacion) VALUES";
                    $query2 = "(:documento,:fotoPerfil,:fotoDocumento, CURRENT_TIMESTAMP)";
                    $query = $con->prepare($query1 . $query2);
                    $query->execute([
                        ':documento'  => self::getDocumento(),
                        ':fotoPerfil'     => $profile > 0 ? 1 : 0,
                        ':fotoDocumento'  => $document > 0 ? 1 : 0         
                    ]);
                }

                if($profile || $document){
                    return ResponseHttp::status200('Imagenes registradas exitosamente');
                }else{
                    return ResponseHttp::status500('No se ha registrado ninguna imagen');
                }
            } catch (\PDOException $e) {
                error_log('UserModel::post -> ' . $e);
                die(json_encode(ResponseHttp::status500()));
            }
    }

    public static function saveBase64Picture($base64Picture, $path, $name){
        
        if(empty($base64Picture))
            return 0;
        
        $base64Picture = str_replace('data:image/jpg;base64,', '', $base64Picture);
        $base64Picture = str_replace('data:image/jpeg;base64,', '', $base64Picture);
        $base64Picture = str_replace(' ', '+', $base64Picture);
        $decodePicture = base64_decode($base64Picture);
        $file = dirname(__DIR__). $path . $name . '.jpg';
        $isSaved = file_put_contents($file, $decodePicture);
        return $isSaved;
    }

}