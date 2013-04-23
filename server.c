/*
 * Autor: Roman Janko
 * Login: xjanko04
 * Datum: 3. 11. 2012
 * Projekt: 1. projekt do predmetu BIS
 * Popis: Server posloucha na portu 8000 a pro kazdeho nove pripojeneho
 *        klienta vytvori vlakno, kde provede jeho autentizaci. Po
 *        uspesne prihlaseni spusti ssh.
 */

#include <stdio.h> 
#include <stdlib.h> 
#include <pthread.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define PORT 8000
#define BUFFER_VELIKOST 100

#define LOGIN "root"
#define HESLO "1234"

/*
 * Vytvori socket a vrati jeho deskriptor.
 */
int Socket(int domain, int type, int protocol)
{
   int n;

   if ( (n = socket(domain, type, protocol)) == -1 )
   {
      fprintf(stderr, "Chyba: Nelze vytvorit socket.\n");
      exit(EXIT_FAILURE);
   }
   else
   {
      return n;
   }
}

/*
 * Navaze IP adresu na socket.
 */
void Bind(int sockid, struct sockaddr *addr, int addresslen)
{
   if ( bind(sockid, addr, addresslen) < 0 ) 
   {
      fprintf(stderr, "Chyba: Nepodarilo se navazat IP adresu na socket.\n");
      exit(EXIT_FAILURE);
   }
}

/*
 * Vytvori frontu pozadavku na spojeni.
 */
void Listen(int sd, int backlog)
{
   if ( listen(sd, backlog) ) 
   {
      fprintf(stderr, "Chyba: Doslo k neocekavane chybe.\n");
      exit(EXIT_FAILURE);
   }
}

/*
 * Uzavre spojeni.
 */
void Close(int sockid)
{
   if (close(sockid) < 0)
   { 
      fprintf(stderr, "Chyba: Nepodarilo se uzavrit socket.\n");
      exit(EXIT_FAILURE);
   } 
}

/*
 * Zkontroluje login a heslo. Pri spravnem overeni uzivatele vraci true. 
 */
bool over_uzivatele(char *login, char *heslo)
{
   if ( strcmp(login, LOGIN) == 0 && strcmp(heslo, HESLO) == 0 )
      return true;
   else
      return false;
}

/*
 * Precte zpravu od klienta. Zaroven orizne posledni 2 znaky (enter).
 */
void Read(int sd, char *buf)
{
   int ret = 0;

   if( ( ret = read(sd, buf, BUFFER_VELIKOST) ) < 0 )
   {
      fprintf(stderr, "Chyba: Nepodarilo se precist zpravu od klienta!\n");
   }
   else
   {
      // oriznu enter
      buf[ret-2] = '\0';
      buf[ret-1] = '\0';
   }
}

/*
 * Odesle zpravu klientovi.
 */
void Write(int sd, char zprava[])
{
	//odeslu zpravu klientovi
	if( write(sd,zprava,strlen(zprava)) < 0 )
   {
      fprintf(stderr, "Chyba: Nepodarilo se odeslat zpravu klientovi!\n");
	}
}

/*
 * Funkce se spusti pri vytvoreni noveho klienta - takovy main().
 * Provede autentizaci a pripadne spusti ssh.
 */
void *obsluzna_funkce_pro_klienta(void *socket)
{
   int sd = (int) socket;
   char login[BUFFER_VELIKOST], heslo[BUFFER_VELIKOST];
   bool uzivatel_overen = false;

   // overim uzivatele
   while ( !uzivatel_overen )
   {
      Write(sd, "Login: ");
      Read(sd, login);

      Write(sd, "Heslo: ");
      Read(sd, heslo);
      
      if ( ( uzivatel_overen = over_uzivatele(login, heslo) ) == false )
      {
         Write(sd, "Spatny login nebo heslo!\n");
      }      
   }
   
   // spustim ssh
   system("/usr/sbin/sshd");
   Write(sd, "Spusteno sshd!\n");

   pthread_exit(EXIT_SUCCESS);
}

void main()
{
   int sd, t;
   struct sockaddr_in sin;
   socklen_t sinlen;
   pthread_t vlakno_klienta;

   // vytvorim soket, pouziji protokol TCP
   sd = Socket(AF_INET, SOCK_STREAM, 0);

   // zaplnim strukturu sockaddr_in
   sin.sin_family = AF_INET;              // rodina protokolu
   sin.sin_port = htons(PORT);            // cislo portu
   sin.sin_addr.s_addr  = INADDR_ANY;

   // navazani IP adresy na socket
   Bind(sd, (struct sockaddr *)&sin, sizeof(sin));

   // vytvoreni fronty pozadavku na spojeni
   Listen(sd, 5);

   // smycka, ve ktere cekam na spojeni
   while (1)
   {
      // prijmu spojeni
      if ( (t = accept(sd, (struct sockaddr *) &sin, &sinlen)) <0 )
      {
         fprintf(stderr, "Chyba: Nepodarilo se prijmout nove spojeni!\n");
         continue;
      }

      printf("Pripojen novy klient: %s:%d\n", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
      
      // vytvorim vlakno pro noveho klienta
      if ( pthread_create(&vlakno_klienta, 0, obsluzna_funkce_pro_klienta, (void *)t) != 0 )
      {
         fprintf(stderr, "Chyba: Nepodarilo se vytvorit vlakno pro noveho klienta!\n");
         continue;
      }
   }

   // zavru socket
   Close(sd);
}


