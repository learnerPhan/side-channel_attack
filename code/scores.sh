#!/bin/bash
graph=$PWD
echo "set xlabel 'Key guess'">>script.gnu
echo "set autoscale" >>script.gnu
echo "set autoscale fix" >>script.gnu
echo "set style data histogram" >>script.gnu
echo "set key outside left box" >>script.gnu
echo "set style fill solid border -1" >>script.gnu
echo "set style histogram cluster gap 1" >>script.gnu
echo "set boxwidth 3.3" >>script.gnu
echo "set term png">>script.gnu
for ((i=0 ; 15 - $i ; i++))
    do
        echo "set output 'test$i'" >>script.gnu
	echo "plot '$graph/$1' index $i with boxes title 'Byte $i'" >>script.gnu
done
echo 'exit'>> script.gnu

cd Scores
mkdir $1
cd $1
gnuplot ../../script.gnu

ppw=$PWD
cd $graph
rm script.gnu
mv $1 $ppw
