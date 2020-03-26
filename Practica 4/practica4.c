/***************************************************************************
 Fichero: practica4.c
 Descripcion: implementacion de los distintos modulos necesarios para la practica
 
 Compila: sin warnings
 Autor: Andrés Salas Peña y Francisco Vicente Lana
***************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "interface.h"
#include "practica4.h"

/*************************** Variables globales *********************************************/

pcap_t* descr, *descr2;      //Descriptores de la interface de red
pcap_dumper_t * pdumper;     //y salida a pcap
uint64_t cont = 0;	         //Contador numero de mensajes enviados
char interface[10];	         //Interface donde transmitir, por ejemplo "eth0"
uint16_t ID = 1, SEQ = 0;    //Identificador IP y SEQ

/* Controlador para el comando control C */
void handleSignal(int nsignal) {
	printf("Control C pulsado (%"PRIu64")\n", cont);
	pcap_close(descr);
	exit(OK);
}

/* Funcion principal del programa */
int main(int argc, char **argv) {
	/* Declaracion de variables */
	char errbuf[PCAP_ERRBUF_SIZE];
	char fichero_pcap_destino[CADENAS];
	uint8_t IP_destino_red[IP_ALEN];
	uint16_t MTU;
	uint16_t datalink;
	uint16_t puerto_destino;
	char data[IP_DATAGRAM_MAX];
	uint16_t pila_protocolos[CADENAS];

	int long_index = 0;
	char opt;
	char flag_iface = 0, flag_ip = 0, flag_port = 0, flag_file = 0;
	FILE *f = NULL;

	/* Estructura para leer los parametros de entrada */
	static struct option options[] = {
		{"if", required_argument, 0, '1'},
		{"ip", required_argument, 0, '2'},
		{"pd", required_argument, 0, '3'},
		{"f", required_argument, 0, '4'},
		{"h", no_argument, 0, '5'},
		{0, 0, 0, 0}
	};

	/* Dos opciones: leer de stdin o de fichero, adicionalmente para pruebas si no se introduce argumento se considera que el mensaje es "Payload" */
	while ((opt = getopt_long_only(argc, argv, "1:2:3:4:5", options, &long_index)) != -1) {
		switch (opt) {
			/* Interfaz */
			case '1' :
				flag_iface = 1;
				sprintf(interface, "%s", optarg);
				break;

			/* IP */
			case '2' : 
				flag_ip = 1;
				/* Leemos la IP a donde transmitir y la almacenamos en orden de red */
				if (sscanf(optarg,"%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"",
				                   &(IP_destino_red[0]), &(IP_destino_red[1]), &(IP_destino_red[2]), &(IP_destino_red[3])) != IP_ALEN) {
					printf("Error: Fallo en la lectura IP destino %s\n", optarg);
					exit(ERROR);
				}
				break;

			/* Puerto */
			case '3' :
				flag_port = 1;
				/* Leemos el puerto a donde transmitir y la almacenamos en orden de hardware */
				puerto_destino = atoi(optarg);
				break;

			/* Archivo de datos */
			case '4' :
				if (strcmp(optarg, "stdin") == 0) { /* Entrada estandar */
					if (fgets(data, sizeof(data), stdin) == NULL) {
						printf("Error leyendo desde stdin: %s %s %d.\n", errbuf,__FILE__,__LINE__);
						return ERROR;
					}
					sprintf(fichero_pcap_destino, "%s%s", "stdin", ".pcap");
				} else { /* Entrada por fichero */
					sprintf(fichero_pcap_destino, "%s%s", optarg, ".pcap");
					f = fopen(optarg, "r");
					if (!f) {
						printf("Error abriendo el fichero. \n");
						exit(ERROR);
					}
					if (fgets(data, sizeof(data), f) == NULL) {
					  	printf("Error leyendo desde fichero: %s %s %d.\n",errbuf,__FILE__,__LINE__);
						return ERROR;
					}
					fclose(f);
				}
				flag_file = 1;
				break;

			/* Resto de casos erroneos */
			case '5' : printf("Ayuda. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;

			case '?' : printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;

			default: printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;
        }
    }
    /* Se han introducitdo los argumentos obligatorios */
	if ((flag_iface == 0) || (flag_ip == 0) || (flag_port == 0)) {
		printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n", argv[0], argc);
		exit(ERROR);
	} else {
		printf("Interface:\n\t%s\n", interface);
		printf("IP:\n\t%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\n", IP_destino_red[0], IP_destino_red[1], IP_destino_red[2], IP_destino_red[3]);
		printf("Puerto destino:\n\t%"PRIu16"\n", puerto_destino);
	}

	/* Sin archivo de datos, envio de payload */
	if (flag_file == 0) {
		sprintf(data, "%s", "Payload ");
		sprintf(fichero_pcap_destino, "%s%s", "debugging",".pcap");
	}

	if (signal(SIGINT, handleSignal) == SIG_ERR) {
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		return ERROR;
	}
	/* Inicializamos las tablas de protocolos */
	if (inicializarPilaEnviar() == ERROR) {
      	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	/* Leemos el tamano maximo de transmision del nivel de enlace */
	if (obtenerMTUInterface(interface, &MTU) == ERROR) {
		return ERROR;
	}
	/* Descriptor de la interface de red donde inyectar trafico */
	if ((descr = pcap_open_live(interface, MTU+ETH_HLEN, 0, 0, errbuf)) == NULL) {
		printf("Error: pcap_open_live(): %s %s %d.\n", errbuf,__FILE__,__LINE__);
		return ERROR;
	}

	datalink = (uint16_t)pcap_datalink(descr); /* DLT_EN10MB==Ethernet */

	/* Descriptor del fichero de salida pcap para debugging */
	descr2 = pcap_open_dead(datalink, MTU+ETH_HLEN);
	pdumper = pcap_dump_open(descr2, fichero_pcap_destino);

	/* Formamos y enviamos el trafico, debe enviarse un unico segmento por llamada a enviar() aunque luego se traduzca en mas de un datagrama */
	/* Primero un paquete UDP */
	/* Definimos la pila de protocolos que queremos seguir */
	pila_protocolos[0] = UDP_PROTO; pila_protocolos[1] = IP_PROTO; pila_protocolos[2] = ETH_PROTO;

	/* Rellenamos los parametros necesario para enviar el paquete a su destinatario y proceso */
	Parametros parametros_udp; 
	memcpy(parametros_udp.IP_destino, IP_destino_red, IP_ALEN); 
	parametros_udp.puerto_destino = puerto_destino;

	/* Realizamos el envio */
	if (enviar((uint8_t*)data, strlen(data), pila_protocolos, &parametros_udp) == ERROR) {
		printf("Error: enviar(): %s %s %d.\n", errbuf,__FILE__,__LINE__);
		return ERROR;
	} else {	
		cont++;
	}

	printf("Enviado mensaje %"PRIu64", almacenado en %s\n\n\n", cont, fichero_pcap_destino);

	/* Luego, un paquete ICMP en concreto un ping */
	pila_protocolos[0] = ICMP_PROTO; pila_protocolos[1] = IP_PROTO; pila_protocolos[2] = ETH_PROTO;
	Parametros parametros_icmp;
	parametros_icmp.tipo = PING_TIPO; 
	parametros_icmp.codigo = PING_CODE; 
	memcpy(parametros_icmp.IP_destino, IP_destino_red, IP_ALEN);
	if (enviar((uint8_t*)"Probando a hacer un ping", strlen("Probando a hacer un ping"), pila_protocolos, &parametros_icmp) == ERROR) {
		printf("Error: enviar(): %s %s %d.\n", errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else {
		cont++;
	}
	printf("Enviado mensaje %"PRIu64", ICMP almacenado en %s\n\n", cont, fichero_pcap_destino);

	/* Cerramos descriptores*/
	pcap_close(descr);
	pcap_dump_close(pdumper);
	pcap_close(descr2);

	return OK;
}

/****************************************************************************************
* Nombre: enviar 									*
* Descripcion: Esta funcion envia un mensaje						*
* Argumentos: 										*
*  -mensaje: mensaje a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen mensaje						*
*  -parametros: parametros necesario para el envio (struct parametros)			*
* Retorno: OK/ERROR									*
****************************************************************************************/
uint8_t enviar(uint8_t* mensaje, uint64_t longitud, uint16_t* pila_protocolos, void *parametros) {
	uint16_t protocolo = pila_protocolos[0];
	printf("Enviar(%"PRIu16") %s %d.\n", protocolo,__FILE__,__LINE__);
	if (protocolos_registrados[protocolo] == NULL) {
		printf("Protocolo %"PRIu16" desconocido\n",protocolo);
		return ERROR;
	}
	else {
		return protocolos_registrados[protocolo](mensaje, longitud, pila_protocolos, parametros);
	}
	return ERROR;
}


/***************************TODO Pila de protocolos a implementar************************************/

/****************************************************************************************
* Nombre: moduloUDP 									*
* Descripcion: Esta funcion implementa el modulo de envio UDP				*
* Argumentos: 										*
*  -mensaje: mensaje a enviar								*
*  -longitud: bytes que componen mensaje						*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/
uint8_t moduloUDP(uint8_t* mensaje, uint64_t longitud, uint16_t* pila_protocolos,void* parametros) {
	/* Declaracion de variables */
	uint8_t segmento[UDP_SEG_MAX] = {0};
	uint16_t puerto_origen = 0, checksum = 0;
	uint16_t aux16;
	uint32_t pos = 0;
	uint16_t protocolo_inferior = pila_protocolos[1];
	uint64_t len = longitud + UDP_HLEN;

	printf("modulo UDP(%"PRIu16") %s %d.\n", protocolo_inferior,__FILE__,__LINE__);

	/* Comprobamos que la longitud del mensaje no es demasiado larga */
	if (longitud > (pow(2, 16) - UDP_HLEN)) {
		printf("Error: mensaje demasiado grande para UDP (%f)\n", (pow(2, 16)-UDP_HLEN));
		return ERROR;
	}

	Parametros datos = *((Parametros*)parametros);
	uint16_t dest = datos.puerto_destino;
	
	if (obtenerPuertoOrigen(&puerto_origen) == ERROR) {
		printf ("Error: fallo al obtener el Puerto de Origen\n");
		return ERROR;
	}

	/* Escritura puerto origen */
	aux16 = htons(puerto_origen);
	memcpy(segmento + pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);
	
	/* Escritura puerto destino */
	aux16 = htons(dest);
	memcpy(segmento + pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	/* Escritura campo longitud */
	aux16 = htons(len);
	memcpy(segmento + pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	/* Escritura suma de control */
	aux16 = htons(checksum);
	memcpy(segmento + pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	/* Escritura datos */
	memcpy(segmento + pos, mensaje, longitud);
	pos += longitud;

	return protocolos_registrados[protocolo_inferior](segmento, pos, pila_protocolos, parametros);
}

/****************************************************************************************
* Nombre: moduloIP 									*
* Descripcion: Esta funcion implementa el modulo de envio IP				*
* Argumentos: 										*
*  -segmento: segmento a enviar								*
*  -longitud: bytes que componen el segmento						*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/
uint8_t moduloIP(uint8_t* segmento, uint64_t longitud, uint16_t* pila_protocolos, void* parametros) {
	/* Declaracino de variables */
	uint8_t datagrama[IP_DATAGRAM_MAX] = {0};
	uint16_t aux16;
	uint32_t pos = 0, pos_cs;
	uint8_t IP_origen[IP_ALEN];
	uint16_t protocolo_superior = pila_protocolos[0];
	uint16_t protocolo_inferior = pila_protocolos[2];
	pila_protocolos++;
	/* Variables de mascara */
	uint8_t mascara[IP_ALEN], IP_rango_origen[IP_ALEN], IP_rango_destino[IP_ALEN], gateway[IP_ALEN];

	uint64_t cont_len = longitud; /* Lleva la cuenta de los bytes que aun no han sido enviados */
	uint16_t MTU, fragmento = 0;
	int maxlen_segmento, modulo, i;
	uint8_t version_ihl, service, time, protocol;
	uint16_t len, flags_pos, checksum;

	printf("modulo IP(%"PRIu16") %s %d.\n", protocolo_inferior,__FILE__,__LINE__);

	Parametros datos = *((Parametros*)parametros);
	uint8_t IP_destino[IP_ALEN];
	memcpy (IP_destino, datos.IP_destino, sizeof(uint8_t)*IP_ALEN);

	if (obtenerIPInterface(interface, IP_origen) == ERROR) {
		printf("Error: fallo en la obtención de IP\n");
		return ERROR;
	}

	/* Llamar a ARPrequest(·) adecuadamente y usar ETH_destino de la estructura parametros */
	if (obtenerMascaraInterface(interface, mascara) == ERROR) {
		printf("Error: fallo en la obtención de la mascara\n");
		return ERROR;
	}
	/* Aplicamos la mascara */
	if (aplicarMascara(IP_origen, mascara, IP_ALEN, IP_rango_origen) == ERROR) {
		printf("Error: fallo en la aplicación de la mascara sobre el origen\n");
		return ERROR;
	}
	if (aplicarMascara(IP_destino, mascara, IP_ALEN, IP_rango_destino) == ERROR) {
		printf ("Error: fallo en la aplicación de la mascara sobre el destino\n");
		return ERROR;
	}

	if (memcmp(IP_rango_destino, IP_rango_origen, (IP_ALEN * sizeof(uint8_t))) == 0) { /* En la subred */
		if (ARPrequest(interface, IP_destino, datos.ETH_destino) == ERROR) {
			printf("Error: fallo en la petición interna ARP\n");
			return ERROR;
		}
	} else { /* Fuera de la subred */
		if (obtenerGateway(interface, gateway) == ERROR) {
			printf("Error: fallo en la obtención del gateway\n");
			return ERROR;
		}
		if (ARPrequest(interface, gateway, datos.ETH_destino) == ERROR) {
			printf("Error: fallo en la petición externa ARP\n");
			return ERROR;
		}
	}

	/* Calculo del tamaño maximo del segmento para fragmentar o no */
    if (obtenerMTUInterface(interface, &MTU) == ERROR) {
        printf("Error al obtener la MTU del nivel anterior.\n");
        return ERROR;
    }
    maxlen_segmento = MTU - IP_HEADER;
   
    /* Mientras sea necesario fragmentar */
    while(cont_len > 0) {
        if(cont_len >= maxlen_segmento) { /* Segmento a fragmentar */
            len = MTU;
            flags_pos = (0x1 << 13) + (fragmento * maxlen_segmento / 8);
            cont_len -= maxlen_segmento;
            fragmento++;
        } else { /* Segmento sin fragmentar */
            len = cont_len + IP_HEADER;
            flags_pos = (fragmento * maxlen_segmento / 8);
            cont_len = 0;
            fragmento++;
            /* Comprobacion del checksum) */
            if ((modulo = (maxlen_segmento % 8)) != 0) {
				for (i = 0; i < (8 - modulo); i++) {
					datagrama[IP_DATAGRAM_MAX -1 - i] = 0;
				}
			}
        }

        /* Escritura de los campos version e ihl */
		version_ihl = (0x4 << 4) + IP_HEADER/4; /* dividimos entre cuatro porque ihl viene dado de 4 bytes en 4 bytes */
		memcpy(datagrama + pos, &(version_ihl), sizeof(uint8_t));
		pos += sizeof(uint8_t);

		/* Escritura  tipo de servicio */
		service = 0;
		memcpy(datagrama + pos, &(service), sizeof(uint8_t));
		pos += sizeof(uint8_t);

		/* Escritura del campo longitud */
		aux16 = htons(len);
	    memcpy(datagrama + pos, &aux16, sizeof(uint16_t));
	    pos += sizeof(uint16_t);

	    /* Escritura del campo identificacion, distinto por cada paquete */
	    aux16 = htons(ID);
		memcpy(datagrama + pos, &aux16, sizeof(uint16_t));
		ID++;
		pos += sizeof(uint16_t);

		/* Escritura de los campos de banderas y posicion */
		aux16 = htons(flags_pos);
		memcpy(datagrama + pos, &aux16, sizeof(uint16_t));
		pos += sizeof(uint16_t);

		/* Escritura del campo tiempo de vida, por defecto a 120 */
		time = 120;
		memcpy(datagrama + pos, &time, sizeof(uint8_t)); //MIRAR
		pos += sizeof(uint8_t);

		/* Escritura del campo protocolo, en este caso UDP o ICMP */
		protocol = protocolo_superior;
		memcpy(datagrama + pos, &protocol, sizeof(uint8_t)); //MIRAR
		pos += sizeof(uint8_t);

		/* Escritura del campo suma de control, a cero para calcularlo posteriormente */
		checksum = 0;
		pos_cs = pos;
		aux16 = htons(checksum);
		memcpy(datagrama + pos, &aux16, sizeof(uint16_t));
		pos += sizeof(uint16_t);

		/* Escritura del campo direccion origen */
		memcpy(datagrama + pos, &IP_origen, sizeof(uint8_t)*IP_ALEN);
		pos += sizeof(uint8_t)*IP_ALEN;

		/* Escritura del campo direccion destino */
		memcpy(datagrama + pos, &IP_destino, sizeof(uint8_t)*IP_ALEN);
		pos += sizeof(uint8_t)*IP_ALEN;

		/* Una vez completa la cabecera con el checksum a cero, este se calcula */
		if (calcularChecksum(IP_HEADER, datagrama, (uint8_t *)&checksum) == ERROR) {
			printf ("Error: fallo en la obtencion del checksum");
			return ERROR;
		}
		memcpy(datagrama + pos_cs, &checksum, sizeof(uint16_t));

		/* Escritura del segmento, un fragmento si corresponde  */
		memcpy(datagrama + pos, segmento + ((fragmento - 1) * maxlen_segmento), len - IP_HEADER);
		pos += len - IP_HEADER;
		/* llamada a protocolo de nivel inferior */
		if (protocolos_registrados[protocolo_inferior](datagrama, pos, pila_protocolos, &datos) == ERROR) {
	        printf("Error al registrar los protocolos.\n");
	        return ERROR;
	    }

	    /* Volvemos a inicializar el datagrama y posicion para sucesivos fragmentos */
	    for (i = 0; i < IP_DATAGRAM_MAX; i++) {
	    	datagrama[i] = 0;
	    }
		pos = 0;
	}

	return OK;
}


/****************************************************************************************
* Nombre: moduloETH 									*
* Descripcion: Esta funcion implementa el modulo de envio Ethernet			*
* Argumentos: 										*
*  -datagrama: datagrama a enviar							*
*  -longitud: bytes que componen el datagrama						*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -parametros: Parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/
uint8_t moduloETH(uint8_t* datagrama, uint64_t longitud, uint16_t* pila_protocolos, void *parametros) {
	/* Declaracion de variables */
	uint32_t pos = 0;
	uint16_t protocolo_superior = pila_protocolos[0];
	pila_protocolos++;
	uint8_t trama[ETH_FRAME_MAX]={0};
	struct pcap_pkthdr pkt_header;

	uint16_t aux16;

	printf("modulo ETH(fisica) %s %d.\n",__FILE__,__LINE__);	

	Parametros datos = *((Parametros*)parametros);
	uint8_t ETH_destino[ETH_ALEN];
	memcpy(ETH_destino, datos.ETH_destino, sizeof(uint8_t)*ETH_ALEN);

	uint8_t ETH_origen[ETH_ALEN];

	if (obtenerMACdeInterface(interface, ETH_origen) == ERROR) {
		printf("Error: fallo en la obtención de la MAC");
		return ERROR;
	}

	/* Control de tamanyo */
	if (longitud + ETH_HLEN > ETH_FRAME_MAX) {
		printf("Error: mensaje demasiado grande para ETH");
		return ERROR;
	}

	/* Escritura del campo destino */
	memcpy(trama + pos, ETH_destino, sizeof(uint8_t)*ETH_ALEN);
	pos += sizeof(uint8_t)*ETH_ALEN;

	/* Escritura del campo origen */
	memcpy(trama + pos, ETH_origen, sizeof(uint8_t)*ETH_ALEN);
	pos += sizeof(uint8_t)*ETH_ALEN;

	/* Escritura del campo tipo */
	aux16 = htons(protocolo_superior);
	memcpy(trama + pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	/* Escritura del datagrama */
	memcpy(trama + pos, datagrama, longitud);
	pos += longitud;

	/* Enviar a capa fisica */
	if (pcap_sendpacket(descr, trama, longitud + ETH_HLEN) == -1) {
		printf("Error: fallo en el envio del paquete");
		return ERROR;
	}	

	/* Almacenamos la salida por cuestiones de debugging */
	pkt_header.len = longitud + ETH_HLEN;
	pkt_header.caplen = longitud + ETH_HLEN; 
	gettimeofday(&pkt_header.ts, NULL);

	pcap_dump((u_char *)pdumper, &pkt_header, (u_char *)trama);
	
	return OK;
}

/****************************************************************************************
* Nombre: moduloICMP 									*
* Descripcion: Esta funcion implementa el modulo de envio ICMP				*
* Argumentos: 										*
*  -mensaje: mensaje a anadir a la cabecera ICMP					*
*  -longitud: bytes que componen el mensaje		     *
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/
uint8_t moduloICMP(uint8_t* mensaje, uint64_t longitud, uint16_t* pila_protocolos, void* parametros) {
	/* Declaracion de variables */
	uint32_t pos = 0, pos_cs;
	uint8_t datagrama[ICMP_DATAGRAM_MAX]={0};
	uint8_t tipo, codigo;
	uint16_t checksum, id;
	uint16_t protocolo_inferior = pila_protocolos[1];

	uint16_t aux16;

	/* Control de tamanyo */
	if (longitud > ICMP_DATAGRAM_MAX - ICMP_HLEN) {
		printf("Error: mensaje demasiado grande para ICMP");
		return ERROR;
	}

	/* Escritura del campo tipo, por defecto a 8 */
	tipo = 8;
	memcpy(datagrama + pos, &tipo, sizeof(uint8_t));
	pos += sizeof(uint8_t);

	/* Escritura del campo codigo, por defecto a 0 */
	codigo = 0;
	memcpy(datagrama + pos, &codigo, sizeof(uint8_t));
	pos += sizeof(uint8_t);

	/* Escritura del campo suma de control, de momento a 0 para su posterior calculo */
	pos_cs = pos;
	checksum = 0;
	aux16 = htons(checksum);
	memcpy(datagrama + pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	/* Escritura del campo identificador */
	id = 1;
	aux16 = htons(id);

	memcpy(datagrama + pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	/* Escritura del numero de secuencia */
	aux16 = htons(SEQ);
	memcpy(datagrama + pos, &aux16, sizeof(uint16_t));
	SEQ++;
	pos += sizeof(uint16_t);

	/* Escritura del datagrama asegurando que la longitud sea par para el correcto calculo del checksum */
	if (longitud % 2 != 0) {
		longitud--;
	}
	memcpy(datagrama + pos, mensaje, longitud);
	pos += longitud;

	/* Calculo del checksum */
	if (calcularChecksum(longitud + ICMP_HLEN, datagrama, (uint8_t *)&checksum) == ERROR) {
		printf("Error: fallo en la obtencion del checksum");
		return ERROR;
	}
	memcpy(datagrama + pos_cs, &checksum, sizeof(uint16_t));

	return protocolos_registrados[protocolo_inferior](datagrama, pos, pila_protocolos, parametros);
}


/***************************Funciones auxiliares a implementar***********************************/

/****************************************************************************************
* Nombre: aplicarMascara 								*
* Descripcion: Esta funcion aplica una mascara a un vector				*
* Argumentos: 										*
*  -IP: IP a la que aplicar la mascara en orden de red					*
*  -mascara: mascara a aplicar en orden de red						*
*  -longitud: bytes que componen la direccion (IPv4 == 4)				*
*  -resultado: Resultados de aplicar mascara en IP en orden red				*
* Retorno: OK/ERROR									*
****************************************************************************************/
uint8_t aplicarMascara(uint8_t* IP, uint8_t* mascara, uint32_t longitud, uint8_t* resultado) {
	int i = 0;
	if (!IP || !mascara || !resultado || longitud <= 0 ) {
		return ERROR;
	}
	for (i = 0; i < longitud; i++) {
		resultado[i] = IP[i] & mascara[i];
	}
	return OK;
}


/***************************Funciones auxiliares implementadas**************************************/

/****************************************************************************************
* Nombre: mostrarPaquete 								*
* Descripcion: Esta funcion imprime por pantalla en hexadecimal un vector		*
* Argumentos: 										*
*  -paquete: bytes que conforman un paquete						*
*  -longitud: Bytes que componen el mensaje						*
* Retorno: OK/ERROR									*
****************************************************************************************/
uint8_t mostrarPaquete(uint8_t * paquete, uint32_t longitud) {
	uint32_t i;
	printf("Paquete:\n");
	for (i = 0; i < longitud; i++) {
		printf("%02"PRIx8" ", paquete[i]);
	}
	printf("\n");
	return OK;
}


/****************************************************************************************
* Nombre: calcularChecksum							     	*
* Descripcion: Esta funcion devuelve el ckecksum tal como lo calcula IP/ICMP		*
* Argumentos:										*
*   -longitud: numero de bytes de los datos sobre los que calcular el checksum		*
*   -datos: datos sobre los que calcular el checksum					*
*   -checksum: checksum de los datos (2 bytes) en orden de red! 			*
* Retorno: OK/ERROR									*
****************************************************************************************/
uint8_t calcularChecksum(uint16_t longitud, uint8_t *datos, uint8_t *checksum) {
    uint16_t word16;
    uint32_t sum = 0;
    int i;
    // make 16 bit words out of every two adjacent 8 bit words in the packet
    // and add them up
    for (i = 0; i < longitud; i = i + 2){
        word16 = (datos[i] << 8) + datos[i + 1];
        sum += (uint32_t)word16;       
    }
    // take only 16 bits out of the 32 bit sum and add up the carries
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    // one's complement the result
    sum = ~sum;      
    checksum[0] = sum >> 8;
    checksum[1] = sum & 0xFF;
    return OK;
}


/***************************Funciones inicializacion implementadas*********************************/

/****************************************************************************************
* Nombre: inicializarPilaEnviar     							*
* Descripcion: inicializar la pila de red para enviar registrando los distintos modulos *
* Retorno: OK/ERROR									*
****************************************************************************************/
uint8_t inicializarPilaEnviar() {
	bzero(protocolos_registrados, MAX_PROTOCOL*sizeof(pf_notificacion));

	if (registrarProtocolo(ETH_PROTO, moduloETH, protocolos_registrados) == ERROR) {
		return ERROR;
	}
	if (registrarProtocolo(IP_PROTO, moduloIP, protocolos_registrados) == ERROR) {
		return ERROR;
	}
	if (registrarProtocolo(UDP_PROTO, moduloUDP, protocolos_registrados) == ERROR) {
		return ERROR; 
	}
	if (registrarProtocolo(ICMP_PROTO, moduloICMP, protocolos_registrados) == ERROR) {
		return ERROR;
	}
	return OK;
}


/****************************************************************************************
* Nombre: registrarProtocolo 								*
* Descripcion: Registra un protocolo en la tabla de protocolos 				*
* Argumentos:										*
*  -protocolo: Referencia del protocolo (ver RFC 1700)					*
*  -handleModule: Funcion a llamar con los datos a enviar				*
*  -protocolos_registrados: vector de funciones registradas 				*
* Retorno: OK/ERROR 									*
*****************************************************************************************/
uint8_t registrarProtocolo(uint16_t protocolo, pf_notificacion handleModule, pf_notificacion* protocolos_registrados) {
	if (protocolos_registrados == NULL ||  handleModule == NULL) {		
		printf("Error: registrarProtocolo(): entradas nulas.\n");
		return ERROR;
	}
	else
		protocolos_registrados[protocolo] = handleModule;
	return OK;
}
