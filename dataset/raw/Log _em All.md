# Log 'em All (967 points)  
> Play to win and log 'em all! Once you've seen all 151 Asciimon, talk to
> Professor Jack for the flag. We've included some data for the first couple
> rooms, you'll have to figure out the rest yourself!  
>  
> `nc -v logemall-a2db138b.challenges.bsidessf.net 666`  
>  
> *(author: iagox86)*

There are two files that accompanies the challenge. The binary itself
`logemall` and some sample data in `sample.tar.bz2`.

## The task  
The `logemall` game is awsome. You connect with a shell using the command
given in the description and is then able to walk on maps, go to NPC's and
interact with them.

The game starts by asking what you would like to be called and which Asciimon
to start with. After that, a map is shown. See below:

![start of game](game.gif)

Walking to the professor gives the task:

> "So, I'm working on a project, but I need you to log all 151  
Asciimon found in the wild. Well, some are in the wild. I'm not sure  
where you'll find the others. But I'm sure you can do it!

So we need to log all Asciimons. He also hints that not all Asciimons exist.

# Writeup  
I (*foens*) attended *BSidesSF 2021 CTF* with the team *kalmarunionen*.

By the end of the event I had reverse engineered the complete binary, but had
not found any vulnerabilities. A hint had also been posted:

> figure out the hidden command to view the encounters table, turn it on, and
> capture a bunch of Asciimon in the same area. Can you break something?

At the time I had already found the hidden commands:

- `encounters off`. Disables encounters.  
- `encounters on`. Enables encounters.  
- `encounters show`. Shows the possible encounters for the current map.  
- `encounters hide`. Hides the encounters again.  
- `fly <arg>` with `<arg>` being one of: `jade`, `deepblue`, `scarlet`, `teal`, `colour`, `gray` or `orange`. Immediatly changes the map.  
- `fight` causes an encounter to happen immediatly with one of the possible encounters for the current map.

I had looked into the logic of fighting, but had been focusing on buffer
overflows. The vulnerability was something else: Look at my reverse
engieneered code and see if you can find it:

```c++

void DoFight_00402c3c(Encounters *encounters,PlayerInfo
*playerInfo,AsciimonIndex *index,  
                    int someBool)

{  
 char *pcVar1;  
 int iVar2;  
 int iVar3;  
 uint uVar4;  
 undefined8 modifier;  
 char local_60 [8];  
 int local_58;  
 uint dmg;  
 int fightAction;  
 uint local_4c;  
 Asciimon *own;  
 int modifierId;  
 Asciimon *enemy;  
 int local_2c;  
 uint local_28;  
 int local_24;  
 uint ownHealth;  
 uint enemyHealth;  
  
 if ((someBool != 0) || (iVar2 = rand(), iVar2 % 100 <=
encounters->chanceOfEncounter_0x4)) {  
   iVar2 = rand();  
   enemy = encounters->encounter_asciimons[iVar2 %
encounters->encounters_0x0];  
   modifierId = rand();  
   modifierId = modifierId % 5;  
   own = playerInfo->asciimon;  
   ShowTerminalHint_0040521a();  
   pcVar1 = enemy->name_0x4;  
   modifier = getModifier_0040280e(modifierId);  
   printf("A %s %s draws near!\n",modifier,pcVar1);  
   iVar2 = IsCaught_0040513f(index,enemy->id_0x0);  
   if (iVar2 == 0) {  
     printf("    Wow! You haven\'t seen a %s before! You make a note\n");  
     putchar('\n');  
     SetAsciimonAsCaught_004050fd(index,enemy->id_0x0);  
   }  
   printf("Your %s gets ready!\n",own->name_0x4);  
   putchar('\n');  
   enemyHealth = enemy->hp_0x24;  
   ownHealth = own->hp_0x24;  
   local_24 = 0;  
   while (0 < (int)enemyHealth) {  
     SmallWait_00405257();  
     printf("Enemy %s:\n",enemy->name_0x4);  
     print_asciimon_004035f5(enemy,1);  
     printf("%d/%d\n\n",(ulong)enemyHealth,(ulong)(uint)enemy->hp_0x24);  
     printf("Your %s:\n",own->name_0x4);  
     print_asciimon_004035f5(own,1);  
     printf("%d/%d\n\n",(ulong)ownHealth,(ulong)(uint)own->hp_0x24);  
     iVar2 = rand();  
     iVar3 = FUN_00402874(modifierId);  
     local_4c = (uint)(iVar2 % 100 < iVar3);  
     local_2c = enemy->defense_0x2c;  
     if (local_4c == 0) {  
       printf("The enemy %s steels itself to defend!\n",enemy->name_0x4);  
       local_2c = local_2c << 1;  
     }  
     else {  
       local_28 = FUN_00402ba2((double)enemy->attack_0x28,(double)own->defense_0x2c);  
       printf("The enemy %s starts winding up an attack for %d damage!\n",enemy->name_0x4,  
              (ulong)local_28);  
     }  
     putchar('\n');  
     printf("What do you do? (a = attack, d = defend, r = run)\n\n> ");  
     fflush(stdout);  
     fightAction = GetFightAction_004026c2();  
     if (fightAction == 0) {  
       uVar4 = rand();  
       if ((uVar4 & 0xff) == 0) {  
         puts("Whiff! You somehow missed!");  
       }  
       else {  
         dmg = FUN_00402ba2((double)own->attack_0x28,(double)local_2c);  
         printf("You attack for %d damage!\n",(ulong)dmg);  
         if ((int)enemyHealth <= (int)dmg) break;  
         enemyHealth = enemyHealth - dmg;  
       }  
       local_24 = 0;  
LAB_00403134:  
       if (local_4c == 0) {  
         printf("The %s is defending!\n",enemy->name_0x4);  
       }  
       else {  
         printf("The enemy hits you for %d damage!\n",(ulong)local_28);  
         if ((int)ownHealth <= (int)local_28) {  
           puts("Your companion faints. Game over! :(\n");  
                   /* WARNING: Subroutine does not return */  
           exit(0);  
         }  
         ownHealth = ownHealth - local_28;  
       }  
     }  
     else {  
       if (fightAction == 1) {  
         puts("You defend!");  
         local_28 = FUN_00402ba2((double)enemy->attack_0x28,(double)(own->defense_0x2c * 2));  
         printf("The enemy ends up doing %d damage\n",(ulong)local_28);  
         goto LAB_00403134;  
       }  
       if (fightAction == 2) {  
         if (enemy->speed_0x30 < own->speed_0x30) {  
           puts("You got away!");  
           SmallWait_00405257();  
           return;  
         }  
         local_24 = local_24 + 1;  
         local_58 = (int)((double)(own->speed_0x30 << 5) / ((double)enemy->speed_0x30 / 4.0) +  
                         (double)(local_24 * 0x1e));  
         iVar2 = rand();  
         uVar4 = (uint)(iVar2 >> 0x1f) >> 0x18;  
         if ((int)((iVar2 + uVar4 & 0xff) - uVar4) < local_58) {  
           puts("You got away!");  
           SmallWait_00405257();  
           return;  
         }  
         puts("You try to escape but fail!");  
         goto LAB_00403134;  
       }  
       if (fightAction == 3) {  
         puts("This is the combat interface!");  
         putchar('\n');  
         puts(  
             "(A)ttack: Your companion will attack the opponent using his attack trait againsttheir defense"  
             );  
         puts("(D)efend: Your companion will defend itself, effectively doubling its defensetrait"  
             );  
         puts(  
             "(R)un: You will attempt to escape; success rate is based on comparing your speedstat to theirs"  
             );  
         puts("(Q)uit: Exit the game");  
         puts("(H)elp: Hi");  
         putchar('\n');  
         goto LAB_00403134;  
       }  
       if (fightAction == 4) {  
         puts("Bye!");  
                   /* WARNING: Subroutine does not return */  
         exit(0);  
       }  
       puts("You twiddle your thumbs");  
     }  
   }  
   SmallWait_00405257();  
   printf("The enemy\'s %s faints! You are victorious!\n\n",enemy->name_0x4);  
   printf("Would you to replace your %s? [y/N]\n\n",own->name_0x4);  
   fgets(local_60,8,stdin);  
   if (local_60[0] == 'y') {  
     playerInfo->asciimon = enemy;  
     enemy->isUsedByPlaner_0x34 = 1;  
     free(own);  
   }  
 }  
```

After the event ended, someone hinted that there was a `use-after-free`
vulnerability.

Each map contains a list of possible encounters, each being an Asciimon. When
seeing a new Asciimon, you note it down. Thus, to `log` all Asciimons, we just
have to meet them. When having faught and won over an Asciimon, you are asked
if you whish to replace your current one with the one you just won over.

That seems all valid. However, if you exchange your Asciimon, then the one you
just faught over **is still a valid encounter**! You can thus fight it
**again** and this time the `free(own)` call will free the one you are now
using. Thus, the `playerInfo->asciimon` now points to a free'd memory region.

Great. So we have found a vulnerability. What to do with it? Well, lets *Log
'em All*! :)

Each Ascsiimon is malloc'ed with a size of `0x40`. There is an `official Name
Rater`. He rates your name, but he also allows you to change it:

```c++  
void nameRater_00404472(PlayerInfo *playerIInfo)

{  
 int iVar1;  
 char *newName;  
 char *pcVar2;  
 size_t sVar3;  
  
 ShowTerminalHint_0040521a();  
 puts("A weird man stands here...");  
 putchar('\n');  
 puts("\"Hello, hello! I am the official Name Rater! Want me to rate your
nickname?\"");  
 putchar('\n');  
 puts("(You have a weird feeling this isn\'t how it normally works...");  
 putchar('\n');  
 iVar1 = promt_00405272("Would you like him to rate your name?",1);  
 ShowTerminalHint_0040521a();  
 if (iVar1 == 0) {  
   puts("He replies:");  
   putchar('\n');  
   puts("\"Fine! Come anytime you like!\"");  
 }  
 else {  
   printf("\"%s, is it? That is a decent nickname! But, would you like
meto\n",playerIInfo->name);  
   puts("give you a nicer nickname? How about it?\"");  
   putchar('\n');  
   iVar1 = promt_00405272("What do you answer?",1);  
   ShowTerminalHint_0040521a();  
   if (iVar1 == 0) {  
     puts("\"Fine! Come anytime you like!\"");  
   }  
   else {  
     puts("\"Fine! What would you like your nickname to be?\"");  
     putchar('\n');  
     printf("> ");  
     newName = (char *)malloc(0x40);  
     memset(newName,0,0x40);  
     pcVar2 = fgets(newName,0x3f,stdin);  
     if (pcVar2 == (char *)0x0) {  
       puts("Could not read from stdin");  
                   /* WARNING: Subroutine does not return */  
       exit(1);  
     }  
     sVar3 = strlen(newName);  
     if (newName[sVar3 - 1] == '\n') {  
       sVar3 = strlen(newName);  
       newName[sVar3 - 1] = '\0';  
     }  
     printf("\"So you want to change \'%s\' to \'%s\'?\"\n",playerIInfo->name,newName);  
     iVar1 = promt_00405272("Is that right?",1);  
     ShowTerminalHint_0040521a();  
     if (iVar1 == 0) {  
       printf("\"OK! You\'re still %s!\"\n",playerIInfo->name);  
       free(newName);  
     }  
     else {  
       free(playerIInfo->name);  
       playerIInfo->name = newName;  
       printf("\"OK! From now on, you\'ll be called %s! That\'s a better name than before!\"\n",  
              playerIInfo->name);  
     }  
   }  
 }  
 return;  
}  
```

Notice that the name is also malloc'ed with a size of `0x40`. The data is read
using `fgets`, so we can also add `null` bytes. Great. We can thus go to the
name rater and change our name, the name will be filled into the same area
that the Asciimon had, we can now control the Asciimon definition.

I have reverse engineered the Asciimon struct to be:

```c++  
struct Asciimon {  
   int id_0x0;  
   char name_0x4[32];  
   int hp_0x24;  
   int attack_0x28;  
   int defense_0x2c;  
   int speed_0x30;  
   int isUsedByPlayer_0x34;  

Original writeup (https://github.com/foens/hacking-
solutions/tree/master/2021/bsides/logemall/readme.md).