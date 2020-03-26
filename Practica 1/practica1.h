/***************************************************************************
 Fichero: practica1.h
 Definicion de macros e inclusion de librerias para resolver el problema 
 especificado en el enunciado de la primera practica de la asignatura 

 Autores: Francisco de Vicente Lana - francisco.vicentel@estudiante.uam.es
 	      Andres Salas Peña - andres.salas@estudiante.uam.es
 Fecha: 28/09/2017
***************************************************************************/

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>

#define OK 0
#define ERROR 1
#define ETH_FRAME_MAX 1514	/* Tamanio maximo trama ethernet */
#define SEGUNDOS_2DIAS 172800 /* Segundos existentes en dos dias */
