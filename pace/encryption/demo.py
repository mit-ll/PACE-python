## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: Framework for demoing the encryption code
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  09 Apr 2015  ATLH    Original file
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

import pyaccumulo
from StringIO import StringIO
import base64
from Crypto.PublicKey import RSA
import subprocess

from pace.encryption.acc_encrypt import AccumuloEncrypt, Encryptor
from pace.encryption.encryption_pki import DummyEncryptionPKI, EncryptionPKIAccumulo
from pace.encryption.AES_encrypt import Pycrypto_AES_CFB
from pace.encryption.encryption_exceptions import DecryptionException

from pace.pki.keygen import KeyGen
from pace.pki.accumulo_keystore import AccumuloKeyStore, AccumuloAttrKeyStore
from pace.pki.frontend import KeyStoreFrontEnd

ABS_PATH = os.path.dirname(__file__)
DEMO_USERS = ABS_PATH + '../pki/user_info.cfg'
PRIV_KEYS = ABS_PATH + '../pki/'

# Default elements to use 
expressive_elems = [('MITLL', '(a&b)|c','Analytics','Rooms','1200'), 
                    ('MITLL', '(a&b)|c','Analytics','Employees','4000'), 
                    ('Boston', '(a&b)|c','Analytics','Population','3000000'),
                    ('Cambridge', '(a&b)|c','Analytics','Population','400000')]

#Tuples of accumulo elements: row, vis, colFam, colQual, and value
vis_elems = [('Analytics', 'a','','','120'), 
            ('Average', 'a&b','','','200'), 
            ('Median', '(a&b)|c','','','160'),
            ('Total', '(a&b)|(c&d)|(b&d)|(b&c)','','','320')]

new_vis_elems = [('Sum', 'c&d','','','1200'), 
                 ('Minimum', 'b','','','120')]
            
empty_vis = [('Sum', '','','','1200')]
descriptions = {'expressive' : "Row contains: Row encrypted with Pycrypto_AES_SIV\n"+\
                                    "ColFamily contains: ColFamily & ColQualifier encrypted with Pycrypto_AES_CFB\n"+\
                                    "ColQualifier contains: Nothing\n"+\
                                    "Value contains: Value encrypted with AES_GCM\n",
                'identity' :  "Row contains: Row unecrypted\n"+\
                                   "ColFamily contains: ColFamily & ColQualifier concatentated\n"+\
                                   "ColQualifier contains: Nothing\n"+\
                                   "Value contains: Value unencrypted \n",
                'vis' : "Value contains: Value encrypted with VIS_AES_CFB",
                'print' : "",
                'vis_print':'',
		'none': "Currently using no encryption scheme"}

schema = { 'expressive' : '[row]\n'+\
              'key_id = Pycrypto_AES_SIV\n'+\
              'encryption = Pycrypto_AES_SIV\n'+\
              '[colFamily]\n'+\
              'key_id = Pycrypto_AES_CFB\n'+\
              'cell_sections = colFamily,colQualifier\n'+\
              'encryption = Pycrypto_AES_CFB\n'+\
              '[value]\n'+\
              'key_id = Pycrypto_AES_CFB\n'+\
              'encryption = Pycrypto_AES_GCM', 
            'identity': '[row]\n'+\
              'key_id = Identity\n'+\
              'encryption = Identity\n'+\
              '[colFamily]\n'+\
              'key_id = Identity\n'+\
              'cell_sections = colFamily,colQualifier\n'+\
              'encryption = Identity\n'+\
              '[value]\n'+\
              'key_id = Identity\n'+\
              'encryption = Identity',
             'vis' : '[value]\n'+\
              'key_id = VIS_AES_CFB\n'+\
              'cell_key_length = 32\n'+\
              'encryption = VIS_AES_CFB',
            'none': '[row]\n'+\
              'key_id = Identity\n'+\
              'encryption = Identity\n',
            'print':'[row]\n'+\
              'key_id = Identity\n'+\
              'encryption = Identity\n',
            'vis_print':'[row]\n'+\
              'key_id = Identity\n'+\
              'encryption = Identity\n'}


def mutation_from_kv_tuple(tup):
    """ Define a pyaccumulo mutation from a (key, value) formatted tuple.
    """
    row, cv, cf, cq, val = tup
    print 'Inserting entry: \n Row - %s,\n Column_Visibility - %s,\n Column_Family - %s,\n Column_Qualifier - %s,\n Value - %s' % (row,cv,cf,cq,val)
    m = pyaccumulo.Mutation(row)
    m.put(cf=cf, cq=cq, cv=cv, val=val)
    return m

def grant_auths(table='demo', user='user3'):
    """
    Grants read/write priviledges for the user 
    for the necessary tables in the demo, also sets
    user's attributes to a,c,d,e
    """    
    print "Setting ", user, "'s attributes to a,c,d,e"
    _ = subprocess.call("/usr/local/accumulo-1.7.0/bin/accumulo shell -u root -p secret -e 'setauths -u "+user+" -s a,c,d,e'", stdout=subprocess.PIPE, shell=True)
    
    tables = ['__VERSION_METADATA__','__KEYWRAP_METADATA__',"VIS_AES_CFB"]
    tables.append(table)
    
    print "Granting read/write access to tables:"
    for tab in tables:
        print "    Table ", tab
        _ = subprocess.call("/usr/local/accumulo-1.7.0/bin/accumulo shell -u root -p secret -e 'grant Table.READ -t "+tab+" -u "+user+"'", stdout=subprocess.PIPE, shell=True)
        _ = subprocess.call("/usr/local/accumulo-1.7.0/bin/accumulo shell -u root -p secret -e 'grant Table.WRITE -t "+tab+" -u "+user+"'", stdout=subprocess.PIPE, shell=True)
        
def write_list_to_table(conn, encrypter, table, data):
    """ Write a list to an Accumulo table.
        Arguments:
        conn - a pyaccumulo connection to an Accumulo instance
        encrypter - an AccumuloEncrypt instance
        table - the name of the table to write to
        data - the list to write to the table, formatted as a list of
               (key, cf, cq, value) tuples
    """

    if not conn.table_exists(table):
        conn.create_table(table)

    wr = conn.create_batch_writer(table)

    for tup in data:
        m = mutation_from_kv_tuple(tup)
        enc_mut = encrypter.encrypt(m)
        for mut in enc_mut:
            wr.add_mutation(mut)

    wr.close()

def run_insert(conn=None,
               data=expressive_elems,
               table='demo',
               config_name = 'expressive',
               PKI_object=None):
    """ Insert a list into the accumulo table specified.
        Arguments:
        conn - the Accumulo connection to use
        data - the list to insert into the Accumulo table
        table - the name of the table to insert to
        default_vis - the default visibility label to use. default: '(a&b)|c'
        config_filept - file pointer to the configuration file for encryption
        PKI_object - matches the interface on encryption PKI OBJECT, default is 
        DummyEncryptionPKI
    """
    if conn is None:
        conn = pyaccumulo.Accumulo(host='localhost',
                                        port=42424,
                                        user='root',
                                        password='secret')
    if PKI_object is None:
        PKI_object = DummyEncryptionPKI(conn=conn)
        
    config_filept = StringIO(schema[config_name])
    encrypter = AccumuloEncrypt(config_filept, PKI_object)
    print "\nEnrypting with the following schema: \n\n" + descriptions[config_name]
    write_list_to_table(conn, encrypter, table, data)

def run_retrieve(conn=None,
               table='demo',
               config_name = 'expressive',
               PKI_object=None):
    """ Retrieves and decrypts values from the specified table,
        outputting the appropriate error messages if not.
        Arguments:
        conn - the Accumulo connection to use
        data - the list to insert into the Accumulo table
        table - the name of the table to insert to
        config_filept - file pointer to the configuration file for encryption
        PKI_object - matches the interface on encryption PKI OBJECT, default is 
        DummyEncryptionPKI
    """
    if conn is None:
        conn = pyaccumulo.Accumulo(host='localhost',
                                        port=42424,
                                        user='root',
                                        password='secret')
    if PKI_object is None:
        PKI_object = DummyEncryptionPKI(conn=conn)
    total = 0
    config_filept = StringIO(schema[config_name])
    decrypter = AccumuloEncrypt(config_filept, PKI_object)

    for entry in conn.scan(table):
        total = total + 1
        try:  
            cell = decrypter.decrypt(entry)
            if config_name == 'print':
                print 'Entry: \n Row - %s,\n Column_Visibility - %s,\n Column_Family - %s,\n Column_Qualifier - %s,\n Value - %s\n' %(base64.b64encode(cell.row),
                      cell.cv,
                      base64.b64encode(cell.cf),
                      base64.b64encode(cell.cq),
                      base64.b64encode(cell.val))
            elif config_name == 'vis_print':
                print 'Entry: \n Row - %s,\n Column_Visibility - %s,\n Column_Family - %s,\n Column_Qualifier - %s,\n Value - %s\n' %(cell.row,
                      cell.cv,
                      cell.cf,
                      cell.cq,
                      base64.b64encode(cell.val))
            else:
                print 'Entry: \n Row - %s,\n Column_Visibility - %s,\n Column_Family - %s,\n Column_Qualifier - %s,\n Value - %s\n' % (cell.row, cell.cv,cell.cf,cell.cq,cell.val)
        except DecryptionException as ve:
            print 'Error: Entry failed to decrypt.'
            print 'Error message:', ve.msg
            print

    print 'Finished, decrypted %d total entries.' %(total)
    
def run_search(conn=None,
               table='demo',
               config_name = 'expressive',
               PKI_object=None,
               row_range='Analytics'):
    """ Retrieves and decrypts values from the specified table,
        outputting the appropriate error messages if not.
        Arguments:
        conn - the Accumulo connection to use
        data - the list to insert into the Accumulo table
        table - the name of the table to insert to
        config_filept - file pointer to the configuration file for encryption
        PKI_object - matches the interface on encryption PKI OBJECT, default is 
        DummyEncryptionPKI
        row_range - the keyword to search for 
    """
    if conn is None:
        conn = pyaccumulo.Accumulo(host='localhost',
                                        port=42424,
                                        user='root',
                                        password='secret')
    if PKI_object is None:
        PKI_object = DummyEncryptionPKI(conn=conn)
        
    total = 0
    enc_config_filept = StringIO(schema[config_name])
    dec_config_filept = StringIO(schema[config_name])
    encrypter = AccumuloEncrypt(enc_config_filept, PKI_object)
    enc_row, _ = encrypter.encrypt_search(row_range, None)
    range = pyaccumulo.Range(srow = enc_row, sinclude = True,
                             erow = enc_row, einclude = True)



    for entry in conn.scan(table, scanrange=range):
        total = total + 1
        try:  
            cell = encrypter.decrypt(entry)
            print "Entry: (%s, %s, %s, %s)" % (cell.row, cell.cf, cell.cq, cell.val)
        except DecryptionException as ve:
            print 'Error: Entry failed to decrypt.'
            print 'Error message:', ve.msg
            print

    print 'Finished, decrypted %d total entries.' %(total)


def run_pki_insert(genpath=DEMO_USERS, user='user1', conn=None):
    """ Insert elements into the PKI as specified by the config
        file located at genpath.
        
        Returns:

        ks - the keystore object initialized this way
    """

    if conn is None:
        print 'Logging in to Accumulo...'
        conn = pyaccumulo.Accumulo(host='localhost', port=42424,
                                   user='root', password='secret')

    print 'Logged in. Creating key store...'
    print 'Deleting existing metadata tables'
    for table_name in ['__VERSION_METADATA__','__ATTR_TABLE__','__KEYWRAP_METADATA__']:
        if conn.table_exists(table_name):
            print 'Deleting table ', table_name
            conn.delete_table(table_name)
    ks = AccumuloAttrKeyStore(conn)
    print 'Key store created.'
    print

    master_secret = 'master secret key'

    print 'Initializing key store with dummy master secret "master secret key"...'
    

            
    kg = KeyGen(master_secret)
    users = KeyGen.file_to_dict(genpath)
    for _, infos in users.itervalues():
        for _, _, metadata, _ in infos:
            if conn.table_exists(metadata):
                print '    Found existing table:', metadata
                print '    Deleting to have a clean slate.'
                conn.delete_table(metadata)

    kg.initialize_users(users, ks)

    #get private keys to unwrap things
    f = open(PRIV_KEYS+user+'_privkey.pem','r')
    priv_key = RSA.importKey(f.read())
    
    print 'Key store initialized.'
    return EncryptionPKIAccumulo(conn, user, priv_key), KeyStoreFrontEnd(ks)

def run_revoke(user, attr, genpath=DEMO_USERS, conn=None):

    if conn is None:
        conn = pyaccumulo.Accumulo(host='localhost', port=42424,
                                   user='root', password='secret')

    ks = AccumuloAttrKeyStore(conn)

    master_secret = 'master secret key'
    kg = KeyGen(master_secret)

    users = KeyGen.file_to_dict(genpath)

    user_keys = {}
    for k_user, k_tuple in users.iteritems():
        user_keys[k_user] = k_tuple[0]
        
    print "Revoking user %s's access to attribute %s." %(user, attr)
    kg.revoke(user, attr, ks, ks, ks, user_keys)
