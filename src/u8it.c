#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

//TYPES
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
//END TYPES

#ifdef __WIN32__
#define MKDIR(x) mkdir(x)
#else
#define MKDIR(x) mkdir(x, 0777)
#endif

//ENDIAN
#define le32 be32
#define le16 be16

u16 be16(u16 x)
{
    return (x>>8) |
   (x<<8);
}

u32 be32(u32 x)
{
    return (x>>24) |
   ((x<<8) & 0x00FF0000) |
   ((x>>8) & 0x0000FF00) |
   (x<<24);
}

//END ENDIAN


//FILE STUFF
u32 align(u32 x, u32 boundary)
{
   if (x % boundary == 0)
      return x;
   else
      return x + boundary - (x % boundary);
}

u32 filesize (FILE *file)
{
   u32 curpos, endpos;
   if ( file == NULL )
      return -1;
   curpos = ftell ( file );
   fseek ( file, 0, 2 );
   endpos = ftell ( file );
   fseek ( file, curpos, 0 );
   return endpos;
}

u32 padded_filesize (FILE *file)
{
   u32 size;
   size = filesize(file);
   size = align(size, 32);
   return size;
}

char *basename (const char * name)
{
   const char * base = name;
   while (*name)
    {
      if (*name++ == '/')
         base = name;
    }
   return (char *) base;
}
//END FILE STUFF

//DEBUG
#define debug printf
//END DEBUG

//U8DEFS
typedef struct
   {
      u16 type; //this is 0x0000 for files and 0x0100 for folders
      u16 name_offset; //offset into the string table from the start of the string table
      u32 data_offset; // absolute offset from U.8- header but it is recursion for directories
      u32 size; // last included file num for directories
   } u8node;


typedef struct
   {
      u32 tag; // 0x55AA382D "U.8-"
      u32 rootnode_offset; // offset to root_node, always 0x20.
      u32 header_size; // size of header from root_node to end of string table.
      u32 data_offset; // offset to data -- this is rootnode_offset + header_size, aligned to 0x40.
      u8 zeroes[16]; //padding
   } u8header;
//END U8DEFS




u8header header;

u32 cur_dataoffset;
u32 cur_stringoffset;
u32 cur_nodeoffset;

u8 * databuffer;
u8 * stringbuffer;
u8 * nodes;

u32 recursion;
u32 numnodes;


u8node packdir (const char * whatdir, u8 root)
{
   DIR * dir = opendir (whatdir);
   u8node self;
   struct dirent * dp;
   u32 i = 0, old_nodeoffset = 0;

   debug("  packdir() called.\n");

   chdir(whatdir);

   if (dir == NULL)
   {
      printf("Error opening directory, exiting.");
      exit(1);
   }

   if(root != 1)
   {
      recursion++; // because we are in a new directory

      old_nodeoffset = cur_nodeoffset; //save for later :)

      self.type = be16(0x0100); //Type: Directory (0x0100)
      self.name_offset = be16(cur_stringoffset);
      self.data_offset = be32(recursion - 1);
      self.size = be32(0); //gets fixed later
      debug("  Directory Node Contstructed.\n");

      nodes = realloc(nodes, cur_nodeoffset + sizeof(u8node)); //adding another node
      memcpy(nodes + cur_nodeoffset, &self, sizeof(u8node));
      cur_nodeoffset += sizeof (u8node);
      numnodes++;
      debug("  Directory Node Added.\n");

      stringbuffer = realloc (stringbuffer, cur_stringoffset + strlen(whatdir) + 1 );
      memcpy(stringbuffer + cur_stringoffset, whatdir, strlen(whatdir) + 1 );
      cur_stringoffset += strlen(whatdir) + 1;
      debug("  Directory Node String Added.\n");
   }

   rewinddir (dir);
   while ((dp = readdir (dir)) != NULL)
   {
      if(strcmp(dp->d_name,".") == 0 || strcmp(dp->d_name,"..") == 0 || !strcmp(dp->d_name, ".DS_Store") || !strcmp(dp->d_name, "._.DS_Store") || !strcmp(dp->d_name, "__MACOSX")) //abort, .DS_Store is a for a stupid osx thing
      {
         i++;
         continue;
      }
      else
      {
	     struct stat info;
	     debug("  Calling stat() on dp->d_name.\n");
         stat(dp->d_name, &info);

         if( S_ISDIR(info.st_mode) != 0) //subdirectory
         {
            printf("Adding Directory: %s\n", dp->d_name);
            packdir(dp->d_name, 0);
         }
         else if (S_ISREG(info.st_mode)) //file
         {
            u8node newnode;
            FILE * nodefile;

            printf("Adding File: %s\n", dp->d_name);

            nodefile = fopen(dp->d_name, "rb"); //open file for node

            newnode.type = be16(0); //type = file (0x0000 means file)
            newnode.name_offset = be16(cur_stringoffset);
            newnode.data_offset = be32(cur_dataoffset); //fixed later
            newnode.size = be32(filesize(nodefile)); //size = size of file
			debug("  Node Created.\n");

            nodes = realloc(nodes, cur_nodeoffset + sizeof(u8node)); //adding another node
            memcpy (nodes + cur_nodeoffset, &newnode, sizeof(u8node)); //add node
            cur_nodeoffset += sizeof(u8node); //increase cur_nodeoffset
            numnodes++; //one more node
			debug("  Node Structure Added.\n");

            databuffer = realloc (databuffer, cur_dataoffset + padded_filesize(nodefile)); //expand buffer as needed
            memset (databuffer+ cur_dataoffset, 0, padded_filesize(nodefile)); //zero out padding
            fread (databuffer + cur_dataoffset, 1, filesize(nodefile), nodefile);  //read file into buffer
            cur_dataoffset += padded_filesize (nodefile); //increase offset
			debug("  Node Data Added.\n");

            stringbuffer = realloc (stringbuffer, cur_stringoffset + strlen(dp->d_name) + 1 ); //expand string buffer, add extra byte for padding
            memcpy(stringbuffer + cur_stringoffset, &dp->d_name, strlen(dp->d_name)+ 1 );
            cur_stringoffset += strlen(dp->d_name) + 1;
			debug("  Node String Added.\n");

            fclose(nodefile);
            debug("  Node File Closed.\n");
         }

      }
      i++;
   }

   if(root != 1)
   {
      recursion--; //going back up a directory

      self.size = be32(numnodes); //update size
      memcpy((u8 *) nodes + old_nodeoffset, &self, sizeof(u8node)); //re-write back into nodes
   }

   closedir (dir);
   chdir("..");
   return self;
}

void packu8 (const char * out, const char * in)
{
   FILE * outfile;
   u8node root, tempnode;
   u32 i, new_nodeoffset = 0;
   u8 * padding;

   printf( "Packing U8 Archive...\n" );

   nodes = NULL;
   cur_nodeoffset = 0;
   numnodes = 1; //root node

   databuffer = NULL; //start allocating memory
   cur_dataoffset = 0;

   stringbuffer = calloc( 1, sizeof( u8 ) ); //for the 0x00 at the start
   cur_stringoffset = sizeof( u8 ); //the root 0x00 at the start of the string table


   packdir (in, 1); //do teh packing

   outfile = fopen( out, "wb" );
   if( outfile==NULL )
      return;

   //set up standard header stuff
   header.tag = be32( 0x55AA382D );
   header.rootnode_offset = be32( 0x000020 );
   header.header_size = be32( cur_nodeoffset + sizeof( u8node ) + cur_stringoffset );
   header.data_offset = be32( align( 0x20 + le32( header.header_size ), 0x40 ) );
   memset( header.zeroes, 0, 16 );

   padding = calloc( 1, le32( header.data_offset ) - 0x20 - le32( header.header_size ) );

   root.type = be16( 0x0100 );
   root.name_offset = be16(0);
   root.data_offset = be32(0);
   root.size = be32( numnodes );

   printf( "Fixing Offsets...\n" );
   for( i=1; i<numnodes; i++ ) //for all nodes...
   {
      tempnode = *( (u8node *) ( nodes + new_nodeoffset ) ); //load into tempnode
      if ( le16( tempnode.type ) == 0) //if it is a file...
      {
         tempnode.data_offset = be32( le32( tempnode.data_offset ) + le32( header.data_offset ) ); //update data offset
         memcpy (nodes + new_nodeoffset, &tempnode, sizeof( u8node ) ); //re-write back into nodes
      }
      new_nodeoffset += sizeof( u8node );
   }

   printf("Writing File...\n");
   fwrite( &header, 1, sizeof( u8header ), outfile ); //write header
   fwrite( &root, 1, sizeof( u8node ), outfile ); //write root node
   fwrite( nodes, 1, cur_nodeoffset, outfile ); // write rest of nodes
   fwrite( stringbuffer, 1, cur_stringoffset, outfile ); //write string table
   fwrite( padding, 1, le32( header.data_offset ) - 0x20 - le32(header.header_size), outfile ); //write padding
   fwrite( databuffer, 1, cur_dataoffset, outfile ); //write data

   fclose(outfile);
   free( padding );
   free( stringbuffer );
   free( databuffer );
   free( nodes );

   printf( "Done!\n" );
}

void unpacku8 (const char * out, const char * in)
{
     FILE * infile, * cur_file;
     u8 * stringtable, * cur_data;
     char * cur_name;
     u8header header;
     u8node root, cur_node;
     u32 cur_pos = 0, numnodes = 0, i = 0, data_offset = 0, header_size = 0, string_size = 0, data_size = 0, break_file[64], cur_dataoffset = 0, cur_size = 0;
     u16 cur_type = 0, cur_nameoffset = 0, cur_index = 0, ret;

     printf("Unpacking U8 Archive...\nIf you don't get any more messages, the unpacking failed.\n\ns");

     infile = fopen (in, "rb");
     if ( infile == NULL )
        return;

     MKDIR(out); //remove second arguement on windows (except cygwin)
     ret = chdir(out);

     printf("Reading U8 Header...\n");
     fread( &header, 1, sizeof(u8header), infile);
     if ( le32(header.tag) != 0x55AA382D) //is it a u8 file?
        return;

     data_offset = le32( header.data_offset );
     header_size = le32( header.header_size );

     printf("Reading Root Node...\n");
     fread( &root, 1, sizeof(u8node), infile );

     numnodes = le32(root.size);
     string_size = data_offset - sizeof(u8header) - numnodes * sizeof(u8node) ;
     data_size = filesize(infile) - data_offset;

    debug("Allocating memory for string table.\n");
     stringtable = malloc(string_size);
     if ( stringtable == NULL )
        return;

    debug("Moving file pointer along and reading string table.\n");
     cur_pos = ftell(infile);
     fseek(infile, sizeof(u8node) * (numnodes - 1), SEEK_CUR);
     fread(stringtable, 1, string_size, infile);
     fseek(infile, cur_pos, SEEK_SET);

     memset(break_file, 0, sizeof(u32) * 64);

    debug("Entering main unpack sequence.\n");
     for( i = 1; i < numnodes; i++ )
     {

          fread(&cur_node, 1, sizeof(u8node), infile );

          cur_type = le16( cur_node.type );
          cur_nameoffset = le16( cur_node.name_offset );
          cur_dataoffset = le32( cur_node.data_offset );
          cur_size = le32( cur_node.size );

          cur_name = (char *) &stringtable[cur_nameoffset];

          switch( cur_type )
          {
                  case 0x0100: //folder
                       printf("Extracting folder: ");
                       printf("%s\n", cur_name);
                       MKDIR(cur_name); //remove second arguement on windows
                       chdir(cur_name);
                       cur_index++;
                       break_file[cur_index] = cur_size;
                       break;
                  case 0x0000: //file
                       printf("Extracting file: ");
                       printf("%s\n", cur_name);

                       cur_file = fopen(cur_name, "wb");
                       if (cur_file == NULL)
                            return;

                       cur_data = malloc(cur_size);
                       if (cur_data == NULL)
                            return;

                       cur_pos = ftell(infile);
                       fseek(infile, cur_dataoffset, SEEK_SET);
                       fread(cur_data, 1, cur_size, infile);
                       fwrite(cur_data, 1, cur_size, cur_file);
                       fseek(infile, cur_pos, SEEK_SET);

                       fclose(cur_file);
                       free(cur_data);
                       break;
                  default:
                       printf("Unknown Type! Type: 0x%X\n", cur_type);
          }
        debug("  Type: 0x%X\n", cur_type);
        debug("  Name Offset: 0x%X\n", cur_nameoffset);
        debug("  Data Offset/Recursion: 0x%X\n", cur_dataoffset);
        debug("  Size: 0x%X\n", cur_size);

        while(break_file[cur_index] == (i + 1) && cur_index > 0)
        {
            debug("Going up a directory...\n");
            chdir(".."); //go back up a directory
            cur_index--;
        }
     }
     fclose(infile);
     free(stringtable);
     printf("Done!\n");
}

int main( int argc, const char * argv[])
{
   if( argc < 2 )
   {
      printf( "Usage: u8it <input> <output> [-pack]\n\nu8it is (c) 2009 icefire. Contact icefire for permission for any non-personal usage. Updates and more available at http://wadder.net/.\n\n");
      return 0;
   }

   if(argc == 3)
   {
       printf("Unack Mode Enabled\n\n");
       unpacku8(argv[2], argv[1]);
   }

   else if(strcmp("-pack", argv[3]) == 0)
   {
       printf("Pack Mode Enabled\n\n");
       packu8( argv[2], argv[1] );
   }

   return 0;
}
