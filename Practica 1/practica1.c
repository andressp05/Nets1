/***************************************************************************
 Fichero: practica1.c
 Implementación del problema especificado en el enunciado de la primera
 practica de la asignatura 

 Autores: Francisco de Vicente Lana - francisco.vicentel@estudiante.uam.es
 	      Andres Salas Peña - andres.salas@estudiante.uam.es
 Fecha: 28/09/2017
***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include "practica1.h"

/* Variables globales */
pcap_t *descr = NULL, *descr2 = NULL;
pcap_dumper_t *pdumper = NULL;
int cont = 0;

/* Controlador del ctl + C */
void handle(int nsignal) {
	printf("\nSe han capturado un total de %d paquetes\n", cont);
	if(descr) {
		pcap_close(descr);
	}
	if(descr2) {
		pcap_close(descr2);
	}
	if(pdumper) {
		pcap_dump_close(pdumper);
	}
	exit(OK);
}

/* Funcion encargada de imprimir un paquete dado mostrando solo el numero
 * de bytes indicado como segundo argumento */
void imprimir_paquete(uint8_t *paquete, int tope) {
	int i;
	printf("Paquete %d: ", cont);
	for (i = 0; i < tope; i++) {
		printf("%02x ", paquete[i]);
	}
	printf("\n");
}

/* Funcion encargado de obtener el minimo entre dos enteros dados */
int min(int a, int b) {
	if (a < b) {
		return a;
	}
	return b;
}

int main(int argc, char **argv) {

	int n; /* Bytes a mostrar en cada paquete */
	char errbuf[PCAP_ERRBUF_SIZE];
	
	int retorno = 0;
	uint8_t *paquete = NULL;
	struct pcap_pkthdr *cabecera = NULL;
	char file_name[256];
	struct timeval time;
	
	if (argc < 2 || argc > 3) { /* Mensaje de ayuda */
		printf("El programa tiene dos funciones:\n\t Si le pasa un argumento, "
		 "se realizara una captura de la intefaz. \n\t Si le pasa dos argumentos, "
		 "se analizara la traza pcap pasada como segundo argumento.\n"
		 "En ambos casos el primer parametro es el numero de bytes a mostrar por cada paquete.\n");
		fflush(stdout);
		return 0;
	}
	
	n = atoi(argv[1]);
	
	if (argc == 2) { /* Captura en vivo */ 
		if (signal(SIGINT, handle) == SIG_ERR) {
			printf("Error: Fallo al capturar la senal SIGINT.\n");
			exit(ERROR);
		}
		
		/* Apertura de interface */
		if ((descr = pcap_open_live("eth0", ETH_FRAME_MAX, 0, 100, errbuf)) == NULL) {
			printf("Error: pcap_open_live(): %s\n", errbuf);
			exit(ERROR);
		}
		
		/* Creacion archivo para volcar la traza */
		descr2 = pcap_open_dead(DLT_EN10MB, ETH_FRAME_MAX);
		if (!descr2) {
			printf("Error al crear el archivo.\n");
			pcap_close(descr);
			exit(ERROR);
		}
		
		gettimeofday(&time, NULL);
		sprintf(file_name, "eth0.%lld.pcap", (long long)time.tv_sec);
		
		pdumper = pcap_dump_open(descr2, file_name);
		if (!pdumper) {
			printf("Error al abrir el dumper: %s.\n", pcap_geterr(descr2));
			pcap_close(descr);
			pcap_close(descr2);
		}
	}

	else if (argc == 3) { /* Captura a partir de una traza dada */
		/* Apertura de una traza previamente capturada */
		if ((descr = pcap_open_offline(argv[2], errbuf)) == NULL) {
			printf("Error: pcap_open_offline(): %s\n", errbuf);
			exit(ERROR);
		}
	}
	
	/* Flujo unico para analizar los paquetes */
	while (retorno != -2) { 
		/* Lectura de cada paquete */
		retorno = pcap_next_ex(descr, &cabecera, (const u_char **)&paquete);

		if (retorno == -1) { /* Se ha producido un error */
			printf("Error al capturar un paquete %s.\n", pcap_geterr(descr));
			pcap_close(descr);
			pcap_close(descr2);
			pcap_dump_close(pdumper);
			exit(ERROR);
		} 
		if (retorno != 0) { /* Se ha realizado una captura */

			if (argc == 2) { 
				cabecera->ts.tv_sec += SEGUNDOS_2DIAS;
				/* Los milisegundos se mantienen al tratarse de la 
				 * "parte decimal" del anterior campo */
			}

			cont++;
			if (pdumper) {
				pcap_dump((uint8_t *)pdumper, cabecera, paquete);
			}
			imprimir_paquete(paquete, min(n, (int) cabecera->len));
		}

	}
	
	printf("\nSe han analizado un total de %d paquetes\n", cont);

	/* Liberacion y cierre de recursos */
	pcap_close(descr);
	pcap_close(descr2);
	pcap_dump_close(pdumper);

	return OK;
}
