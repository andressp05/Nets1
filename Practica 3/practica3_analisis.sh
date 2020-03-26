#!/bin/bash

echo "Bash practica 3, redes de computadores"

#Eliminamos archivos .txt y .jpeg para que no sean sobreescitos
#rm -f *.txt
#rm -f *_o.txt
#rm -f *_d.txt
rm -dfr Graficas General Tamanyos Tiempos Serie

#Generamos los ficheros para estadisticas generales respecto a los protocolos
echo "-> generando traza.txt"
tshark -r analisis.pcap >> traza.txt

echo "-> generando ip.txt"
tshark -r analisis.pcap -T fields -e ip.src -e ip.dst -e frame.len -Y 'ip' >> ip.txt
#el filtrado tambien incluye la posibilidad que sean paquetes vlan cuyo siguiente protocolo es ip

echo "-> generando udp.txt"
tshark -r analisis.pcap -T fields -e udp.srcport -e udp.dstport -e frame.len -Y 'udp' >> udp.txt

echo "-> generando tcp.txt"
tshark -r analisis.pcap -T fields -e tcp.srcport -e tcp.dstport -e frame.len -Y 'tcp' >> tcp.txt

#------------------------------------------------------------------------------------------------------------ [PUNTO 1]
echo "PUNTO 1 (porcentajes protocolos) *********************************"
#Calculamos las estadisticas exigidas mediante awk [PUNTO 1]
echo | awk -v contTOTAL="$(wc -l < traza.txt)" -v contIP="$(wc -l < ip.txt)" -v contUDP="$(wc -l < udp.txt)" -v contTCP="$(wc -l < tcp.txt)" 'BEGIN{}
{} 
END{
	#DEBUG#print "\nPaquetes en total: "contTOTAL"\n IP: "contIP"\n UDP: "contUDP"\n TCP: "contTCP;
	print "Porcentaje de paquetes IP: "contIP*100/contTOTAL"% (No IP: "(contTOTAL-contIP)*100/contTOTAL"%)";
	print "Entre los IP se tiene: "
	print "\tUDP: "contUDP*100/contIP"%\n\tTCP: "contTCP*100/contIP"%\n\tOtros: "(contIP-contUDP-contTCP)*100/contIP"%\n";
}'

#------------------------------------------------------------------------------------------------------------ [PUNTO 2]
echo " "
echo "PUNTO 2 (top direcciones y puertos) ********************************"

echo "->Top 10 direcciones IP:"
echo "    Origen (en bytes).-"
awk '{top[$1] +=  $3;}
END {
	for (i in top) {
		print "\t"top[i]" "i;
	}
}' ip.txt | sort -rnk1 | head -n 10

echo "    Destino (en bytes).-"
awk '{top[$2] += $3;}
END {
	for (i in top) {
		print "\t"top[i]" "i;
	}
}' ip.txt | sort -rnk1 | head -n 10

echo "    Origen (en paquetes).-"
awk '{top[$1] += 1;}
END {
	for (i in top) {
		print "\t"top[i]" "i;
	}
}' ip.txt | sort -rnk1 | head -n 10

echo "    Destino (en paquetes).-"
awk '{top[$2] += 1;}
END {
	for (i in top) {
		print "\t"top[i]" "i;
	}
}' ip.txt | sort -rnk1 | head -n 10

echo "->Top 10 puertos TCP: "
echo "    Origen (en bytes).-"
awk '{top[$1] +=  $3;}
END {
	for (i in top) {
		print "\t"top[i]" "i;
	}
}' tcp.txt | sort -rnk1 | head -n 10

echo "    Destino (en bytes).-"
awk '{top[$2] += $3;}
END {
	for (i in top) {
		print "\t"top[i]" "i;
	}
}' tcp.txt | sort -rnk1 | head -n 10

echo "    Origen (en paquetes).-"
awk '{top[$1] += 1;}
END {
	for (i in top) {
		print "\t"top[i]" "i;
	}
}' tcp.txt | sort -rnk1 | head -n 10

echo "    Destino (en paquetes).-"
awk '{top[$2] += 1;}
END {
	for (i in top) {
		print "\t"top[i]" "i;
	}
}' tcp.txt | sort -rnk1 | head -n 10

echo "->Top 10 puertos UDP: "
echo "    Origen (en bytes).-"
awk '{top[$1] +=  $3;}
END {
	for (i in top) {
		print "\t"top[i]" "i;
	}
}' udp.txt | sort -rnk1 | head -n 10

echo "    Destino (en bytes).-"
awk '{top[$2] += $3;}
END {
	for (i in top) {
		print "\t"top[i]" "i;
	}
}' udp.txt | sort -rnk1 | head -n 10

echo "    Origen (en paquetes).-"
awk '{top[$1] += 1;}
END {
	for (i in top) {
		print "\t"top[i]" "i;
	}
}' udp.txt | sort -rnk1 | head -n 10

echo "    Destino (en paquetes).-"
awk '{top[$2] += 1;}
END {
	for (i in top) {
		print "\t"top[i]" "i;
	}
}' udp.txt | sort -rnk1 | head -n 10

mkdir General
mv traza.txt General
mv ip.txt General
mv udp.txt General
mv tcp.txt General

#------------------------------------------------------------------------------------------------------------ [PUNTO 3]
echo  " "
echo "PUNTO 3 (ECDF's tamanyos)****************************************"
#generamos los ficheros necesarios para este punto
echo "-> generando tam_o.txt"
tshark -r analisis.pcap -T fields -e frame.len -Y 'eth.src eq 00:11:88:CC:33:FC' >> tam_o.txt
echo "-> generando tam_d.txt"
tshark -r analisis.pcap -T fields -e frame.len -Y 'eth.dst eq 00:11:88:CC:33:FC' >> tam_d.txt

echo "-> generando ecdf_tam_o.txt"
awk '{tam[$1] += 1;}
END {
	for (i in tam) {
		print i" "tam[i];
	}
}' tam_o.txt | sort -nk1 >> cdf_tam_o.txt

awk -v cont="$(wc -l < tam_o.txt)" '{
	acum += $2/cont;
	print $1" "acum;
}' cdf_tam_o.txt >> ecdf_tam_o.txt

echo "-> generando ecdf_tam_d.txt"
awk '{tam[$1] += 1;}
END {
	for (i in tam) {
		print i" "tam[i];
	}
}' tam_d.txt | sort -nk1 >> cdf_tam_d.txt

awk -v cont="$(wc -l < tam_d.txt)" '{
	acum += $2/cont;
	print $1" "acum;
}' cdf_tam_d.txt >> ecdf_tam_d.txt

#invocamos a gnuplot para representar estos datos
echo "-> generando la grafica ecdf_tam.jpeg"
gnuplot << __EOF__
set term jpeg
set output "ecdf_tam.jpeg"
set xlabel "Tamanyo del paquete (Bytes)"
set ylabel "Probabilidad"
set title "ECDF de los tamanyos a nivel 2"
set size
plot "ecdf_tam_o.txt" using 1:2 title 'origen' with steps, "ecdf_tam_d.txt" using 1:2 title 'destino' with steps
__EOF__

mkdir Graficas
mv ecdf_tam.jpeg Graficas

echo "-> generando http_o.txt"
tshark -r analisis.pcap -T fields -e ip.len -Y 'tcp.srcport eq 80' >> http_o.txt
echo "-> generando http_d.txt"
tshark -r analisis.pcap -T fields -e ip.len -Y 'tcp.dstport eq 80' >> http_d.txt

echo "-> generando ecdf_http_o.txt"
awk '{tam[$1] += 1;}
END {
	for (i in tam) {
		print i" "tam[i];
	}
}' http_o.txt | sort -nk1 >> cdf_http_o.txt

awk -v cont="$(wc -l < http_o.txt)" '{
	acum += $2/cont;
	print $1" "acum;
}' cdf_http_o.txt >> ecdf_http_o.txt

echo "-> generando ecdf_http_d.txt"
awk '{tam[$1] += 1;}
END {
	for (i in tam) {
		print i" "tam[i];
	}
}' http_d.txt | sort -nk1 >> cdf_http_d.txt

awk -v cont="$(wc -l < http_d.txt)" '{
	acum += $2/cont;
	print $1" "acum;
}' cdf_http_d.txt >> ecdf_http_d.txt

#invocamos a gnuplot para representar estos datos
echo "-> generando la grafica ecdf_http.jpeg"
gnuplot << __EOF__
set term jpeg
set output "ecdf_http.jpeg"
set xlabel "Tamanyo del paquete (Bytes)"
set ylabel "Probabilidad"
set title "ECDF de los tamanyos http"
set size
plot "ecdf_http_o.txt" using 1:2 title 'origen' with steps, "ecdf_http_d.txt" using 1:2 title 'destino' with steps
__EOF__

mv ecdf_http.jpeg Graficas

echo "-> generando dns_o.txt"
tshark -r analisis.pcap -T fields -e ip.len -Y 'udp.srcport eq 53' >> dns_o.txt
echo "-> generando dns_d.txt"
tshark -r analisis.pcap -T fields -e ip.len -Y 'udp.dstport eq 53' >> dns_d.txt

echo "-> generando ecdf_dns_o.txt"
awk '{tam[$1] += 1;}
END {
	for (i in tam) {
		print i" "tam[i];
	}
}' dns_o.txt | sort -nk1 >> cdf_dns_o.txt

awk -v cont="$(wc -l < dns_o.txt)" '{
	acum += $2/cont;
	print $1" "acum;
}' cdf_dns_o.txt >> ecdf_dns_o.txt

echo "-> generando ecdf_dns_d.txt"
awk '{tam[$1] += 1;}
END {
	for (i in tam) {
		print i" "tam[i];
	}
}' dns_d.txt | sort -nk1 >> cdf_dns_d.txt

awk -v cont="$(wc -l < dns_d.txt)" '{
	acum += $2/cont;
	print $1" "acum;
}' cdf_dns_d.txt >> ecdf_dns_d.txt

#invocamos a gnuplot para representar estos datos
echo "-> generando la grafica ecdf_dns.jpeg"
gnuplot << __EOF__
set term jpeg
set output "ecdf_dns.jpeg"
set xlabel "Tamanyo del paquete (Bytes)"
set ylabel "Probabilidad"
set title "ECDF de los tamanyos dns"
set size
plot "ecdf_dns_o.txt" using 1:2 title 'origen' with steps, "ecdf_dns_d.txt" using 1:2 title 'destino' with steps
__EOF__

mv ecdf_dns.jpeg Graficas

mkdir Tamanyos
mv *.txt Tamanyos

#------------------------------------------------------------------------------------------------------------ [PUNTO 4]
echo " "
echo "PUNTO 4 (ECDF's interarrivals)**************************************"

#generamos los ficheros necesarios para este cuarto punto
echo "-> generando inter_tcp_o.txt"
tshark -r analisis.pcap -T fields -e frame.time_delta_displayed -Y 'ip.src eq 53.59.245.211 and tcp' >> inter_tcp_o.txt
echo "-> generando inter_tcp_d.txt"
tshark -r analisis.pcap -T fields -e frame.time_delta_displayed -Y 'ip.dst eq 53.59.245.211 and tcp' >> inter_tcp_d.txt

echo "-> generando ecdf_inter_tcp_o.txt"
awk '{tam[$1] += 1;}
END {
	for (i in tam) {
		print i" "tam[i];
	}
}' inter_tcp_o.txt | sort -nk1 >> cdf_inter_tcp_o.txt

awk -v cont="$(wc -l < inter_tcp_o.txt)" '{
	acum += $2/cont;
	print $1" "acum;
}' cdf_inter_tcp_o.txt >> ecdf_inter_tcp_o.txt

echo "-> generando ecdf_inter_tcp_d.txt"
awk '{tam[$1] += 1;}
END {
	for (i in tam) {
		print i" "tam[i];
	}
}' inter_tcp_d.txt | sort -nk1 >> cdf_inter_tcp_d.txt

awk -v cont="$(wc -l < inter_tcp_d.txt)" '{
	acum += $2/cont;
	print $1" "acum;
}' cdf_inter_tcp_d.txt >> ecdf_inter_tcp_d.txt

#invocamos a gnuplot para representar estos datos
echo "-> generando la grafica ecdf_inter_tcp.jpeg"
gnuplot << __EOF__
set term jpeg
set output "ecdf_inter_tcp.jpeg"
set xlabel "Tiempos interarrival (segundos)"
set xrange [1E-6:*]
set ylabel "Probabilidad"
set logscale x
set title "ECDF de los interarrivals TCP"
plot "ecdf_inter_tcp_o.txt" using 1:2 title 'origen' with steps, "ecdf_inter_tcp_d.txt" using 1:2 title 'destino' with steps 
__EOF__

mv ecdf_inter_tcp.jpeg Graficas

echo "-> generando inter_udp_o.txt"
tshark -r analisis.pcap -T fields -e frame.time_delta_displayed -Y 'udp.srcport eq 1944' >> inter_udp_o.txt
echo "-> generando inter_udp_d.txt"
tshark -r analisis.pcap -T fields -e frame.time_delta_displayed -Y 'udp.dstport eq 1944' >> inter_udp_d.txt

echo "-> generando ecdf_inter_udp_o.txt"
awk '{tam[$1] += 1;}
END {
	for (i in tam) {
		print i" "tam[i];
	}
}' inter_udp_o.txt | sort -nk1 >> cdf_inter_udp_o.txt

awk -v cont="$(wc -l < inter_udp_o.txt)" '{
	acum += $2/cont;
	print $1" "acum;
}' cdf_inter_udp_o.txt >> ecdf_inter_udp_o.txt

echo "-> generando ecdf_inter_udp_d.txt"
awk '{tam[$1] += 1;}
END {
	for (i in tam) {
		print i" "tam[i];
	}
}' inter_udp_d.txt | sort -nk1 >> cdf_inter_udp_d.txt

awk -v cont="$(wc -l < inter_udp_d.txt)" '{
	acum += $2/cont;
	print $1" "acum;
}' cdf_inter_udp_d.txt >> ecdf_inter_udp_d.txt

#invocamos a gnuplot para representar estos datos
echo "-> generando la grafica ecdf_inter_udp_o.jpeg"
if [ ! -s "ecdf_inter_udp_o.txt" ]; then 
	echo "no hay datos en el fichero"
else
	gnuplot << __EOF__
	set term jpeg
	set output "ecdf_inter_udp_o.jpeg"
	set xlabel "Tiempos interarrival (segundos)"
	set xrange [1E-6:*]
	set ylabel "Probabilidad"
	set logscale x
	set title "ECDF de los interarrivals UDP origen"
	plot "ecdf_inter_udp_o.txt" using 1:2 title 'origen' with steps
__EOF__
fi

echo "-> generando la grafica ecdf_inter_udp_d.jpeg"
gnuplot << __EOF__
set term jpeg
set output "ecdf_inter_udp_d.jpeg"
set xlabel "Tiempos interarrival (segundos)"
set xrange [1E-6:*]
set ylabel "Probabilidad"
set logscale x
set title "ECDF de los interarrivals UDP destino"
plot "ecdf_inter_udp_d.txt" using 1:2 title 'destino' with steps
__EOF__

mv ecdf_inter_udp_d.jpeg Graficas

mkdir Tiempos
mv *.txt Tiempos

#------------------------------------------------------------------------------------------------------------ [PUNTO 5]
echo "PUNTO 5 (Serie Temporal)******************************************"

echo "-> generando bw_o.txt"
tshark -r analisis.pcap -T fields -e frame.time_relative -e frame.len -Y 'eth.src eq 00:11:88:CC:33:FC' >> bw_o.txt
echo "-> generando bw_d.txt"
tshark -r analisis.pcap -T fields -e frame.time_relative -e frame.len -Y 'eth.dst eq 00:11:88:CC:33:FC' >> bw_d.txt

awk 'BEGIN{cont = 1;}
{
	if (cont > $1) {
		tiempo[cont] += $2;
	} else {
		cont++;
	}
}
END{
	for (i = 1; i < cont; i++) {
		print i - 1" "tiempo[i] * 8;
	}
}' bw_o.txt >> bw_cont_o.txt

awk 'BEGIN{cont = 1;}
{
	if (cont > $1) {
		tiempo[cont] += $2;
	} else {
		cont++;
	}
}
END{
	for (i = 1; i < cont; i++) {
		print i - 1" "tiempo[i] * 8;
	}
}' bw_d.txt >> bw_cont_d.txt

echo -n "-> generando la grafica bw.jpeg"
gnuplot <<__EOF__
set term jpeg
set output "bw.jpeg"
set xlabel "Tiempos de captura (segundos)"
set ylabel "Tamanyo (bits)"
set title "Serie Temporal ancho de banda consumido"
plot "bw_cont_o.txt" using 1:2 title 'origen' with lines, "bw_cont_d.txt" using 1:2 title 'destino' with lines
__EOF__

mv bw.jpeg Graficas

mkdir Serie
mv *.txt Serie

echo "[fin]"
exit
