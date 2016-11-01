## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ATLH
##  Description: Secret sharing for visibility 
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##   5 Mar 2015  ATLH    Original file 
## **************

import os
import sys
this_dir = os.path.dirname(os.path.dirname(__file__))
base_dir = os.path.join(this_dir, '../..')
sys.path.append(base_dir)

from Crypto import Random 
import StringIO
import base64

from pace.pki.abstractpki import PKILookupError
from pace.encryption.visibility.vis_parser import VisParser, VisNode, VisTree, NodeType
 

def byte_xor(bytestring1, bytestring2):
        '''
        Calculates the xor of two equal length byte strings
        returns a byte string (not a byte array)
        '''
        byte_array1 = bytearray(bytestring1)
        byte_array2 = bytearray(bytestring2)
        return bytes(bytearray(b1 ^ b2 for (b1, b2) in zip(byte_array1, byte_array2)))
    
class SecretVisNode(VisNode):
    '''
    Basic building block for Secret-sharing visibility trees.
    Subclasses existing VisNode, but also stores the 
    corresponding share for that node. Shares are treated 
    as bytestrings. In the case of: 
    
    AND - the share is the bitwise xor of all its
          children
    OR - the share is the same as its children
    TERM - a random share 
    '''
    def __init__(self, start, end=None,type=NodeType.TERM, 
                 share='', attribute='', encrypted_share=''):
        super(SecretVisNode, self).__init__(start, 
                                            end=end,
                                            type=type)
        self.share = share
        self.attribute = attribute
        self.encrypted_share = encrypted_share
        
    @staticmethod    
    def copy_node(node):
        '''
        Returns a copy of the node with the exception of 
        its children 
        '''
        if type(node) is SecretVisNode:
            return SecretVisNode(start=node.start, 
                             end=node.end,
                             type=node.type,
                             share=node.share,
                             attribute=node.attribute,
                             encrypted_share=node.encrypted_share)
        else:
            return SecretVisNode(start=node.start,
                                 end=node.end,
                                 type=node.type)
    
        
class SecretVisTree(VisTree):
    '''
    Represents the logic for computing and dealing with 
    secret shares 
    
    TODO: In future it may be nice to have the ability
    to specify the random seed used to generate the shares
    for repeatability
    '''
    
    def __init__(self, root, expression, secret=None):
        '''
        Arguments:
        root - either a VisTree or SecretVisTree
        expression - corresponding visibility expression 
        secret - (byte_string) secret for the tree 
        '''
        self.expression = expression
        self.secret = secret
        self.terms = {}
        if type(root) == VisNode: 
            #copy over nodes if it is a vis_tree
            self.root = self._copy_from_vis_tree(root)
        else:
            self.root = root 
    
    def _copy_from_vis_tree(self, node):
        '''
        Arguments:
        node - a top level vis node to copy
                
        Returns: A copy of vistree as the SecretVisTree
        '''
        if node.type == NodeType.TERM:
            new_node = SecretVisNode.copy_node(node)
            new_node.attribute = node.getTerm(self.expression)
            return new_node
            
        else:
            new_node = SecretVisNode.copy_node(node)
            _ = [new_node.add(self._copy_from_vis_tree(c))
                  for c in node.children]       
            return new_node
        
    def set_attributes(self, vis_tree):
        '''
        Arguments:
        vis_tree - takes in vis_tree of the same structure
         as self
         
        Updates the attributes in the nodes according to 
        vis_tree
        '''
        self._set_attributes(self.root,vis_tree.root,vis_tree.expression)
        
    def _set_attributes(self, node, vis_node, expression):
        '''
        Arguments:
        node - a top level node to set
        vis_node - the vis_node to get attribute from 
        expression - vis_expression to set 
                
        '''
        if node.type == NodeType.TERM:
            node.attribute = vis_node.getTerm(expression)         
        else:
            _ = [self._set_attributes(c,vc,expression) 
                 for (c, vc) in zip(node.children, vis_node.children)]       


    def optimal_decryption_tree(self, key_container, encrypted=True):
        '''     
        If the terms contained in the key_object passed in satisfy the expression; 
        calculates the minimal tree traversal (and therefore
        minimal number of shares to be recombined) in order to reach the 
        leaves (or recombine the share)
        
        Arguments:
            key_container - Keytor object that contains the key_id and key_object,
                 used to look up attribute keys as needed when a term
                 is run across
            encrypted - whether the node is encrypted or not, used 
                for unit testing. When set to FALSE a default
                version number is used rather than extracted 
                from the ciphertext

        Returns:
            A three tuple of (match, SecretVisTree, keys). Match is a a boolean
            of whether the terms satisfied the tree. If match is True,
            returns a new SecretVisTree with the trimmed structure. 
            If False, it returns None. Keys is a dictionary of attribute
            to key mappings built as the tree is traversed and the keys are
            pulled back. 
        '''
        
        self.terms = {}
        #call recursive helper function for tree traversal
        (match, num_decryption, node) = self._optimal_decryption_tree(self.root, 
                                                                      key_container,
                                                                      encrypted)
                                                                  
        return (match, SecretVisTree(node, self.expression, self.secret), self.terms)
    
    def _have_term(self, term, key_container, version):
        """
        Helper function to determine if user has particular attribute key
            1. First checks the list of terms if it contains the attribute. If so,
                returns True.
            2. If the key is returned, this adds the key to terms and returns True. 
                Otherwise, this returns False."
        
        Arguments:
            term: the attribute to check for
            key_container - Keytor object that contains the key_id and key_object,
                 used to look up attribute keys as needed when a term
                 is run across
            version - (string) version of the key to check
        """
        if term in self.terms.keys():
            return True
        else: 
            try:
                key = key_container.key_object.get_attribute_key(key_container.key_id, 
                                                                  term,
                                                                  int(version))
                self.terms[term] = key
                return True
            except PKILookupError: 
                return False
            
    def _optimal_decryption_tree(self, share_node, key_container, encrypted):
        '''
        
        Recursive helper function for optimal_decryption_tree
        
        Arguments:
            share_node - the current top level node of the share_tree
            key_container - Keytor object that contains the key_id and key_object,
                 used to look up attribute keys as needed when a term
                 is run across
            encrypted - whether the node is encrypted or not, used 
                        for unit testing. When set to FALSE a default
                        version number is used rather then extracted 
                        from the ciphertext
        Returns:
            A four tuple of (match, num_decrypt, root, keys). Match is 
            a boolean value of whether the terms could satisfy
            the expression. Num_decrypt is the minimum number of
            shares that need to be combined. Root is the root of the tree
            that represent the minimal tree traversal, it is a
            strict subset of the original tree and with the 
            terms provided the expression is satisfied. In the
            case where match is False, num_decryptions and root are set to
            0 and None respectively. Keys contains a dictionary of attributes
            and their correspond keys that have been looked up so far. 
        '''
        
        
        #Base case, have reached a term and have to see if it
        #is in the listed terms 
        if share_node.type == NodeType.TERM:
            share_copy = SecretVisNode.copy_node(share_node)
            #if not encrypted, then we have no version info for the key
            if encrypted is False:
                version = '1'
            else:
                version = share_copy.encrypted_share.rsplit('ver',1)[1]
                
            return (self._have_term(share_copy.attribute,
                                    key_container,
                                    version),
                    1,
                    share_copy)
        #And case: must see if all the children satisfy and num_encryptions
        #is the maximum number for all of the children  
        elif share_node.type == NodeType.AND:
            share_copy = SecretVisNode.copy_node(share_node)
            max_decrypt = 0
            for c in share_node.children:
                (match, num_decrypt, child_copy) =\
                        self._optimal_decryption_tree(c, key_container,
                                                      encrypted)
                if not match:
                    return (match, 0, None)
                max_decrypt = max(max_decrypt, num_decrypt)
                share_copy.add(child_copy)
            return (True, max_decrypt+len(share_copy.children)-1, share_copy)
        #OR case: see if one or more children satisfy, if so take the 
        #one that has the minimum number decryptions as the only child. 
        elif share_node.type == NodeType.OR:
            share_children = []
            num_decrypts = []
            for c in share_node.children:
                (match, num_decrypt, child_copy) =\
                     self._optimal_decryption_tree(c, key_container,
                                                   encrypted)
                if match:
                    share_children.append(child_copy)
                    num_decrypts.append(num_decrypt)
            if not share_children:    
                return (False, 0, None)
            else:
                share_node_copy = SecretVisNode.copy_node(share_node)
                min_decrypt = min(num_decrypts)
                share_node_copy.add(share_children[num_decrypts.index(min_decrypt)])
                return (True, min_decrypt, share_node_copy)
        
    def print_shares(self, encrypted=False):
        """
        Print the shares, used primarily for testing
        """
        s = StringIO.StringIO()
        self._print_shares(self.root, s, encrypted)
        s_string = s.getvalue()
        s.close()
        return s_string
    
    def _print_shares(self, root, output, encrypted=False):
        """
        Arguments:
         root: VisNode to turn into a string representation
         out_put: StringIO object in which the string 
                  description is placed. 
                  
        Side Effects: Returns nothing, but string representation
           of the shares is placed in the out_put object.    
        """
        #case of empty root
        if root is None:
           output.write('')
           return 
       
        if root.type == NodeType.TERM:
            if not encrypted:
                output.write('"'+str(root.share)+'"')
            else:
                output.write('"'+str(root.encrypted_share)+'"')
        else:
            sep = ''
            for c in root.children:
                output.write(sep)
                parens = (c.type != NodeType.TERM) and (root.type != c.type)   
                if parens:
                    output.write("(")
                self._print_shares(c, output, encrypted)
                if parens:
                    output.write(")")
                if root.type == NodeType.AND:
                    sep = '&'
                else: 
                    sep = "|"
    
    def verify_shares(self):
        '''
        Verifies that the shares combine to the secret 
        '''
        return self._verify_shares(self.root)
    
    def _verify_shares(self, node): 
        '''
        Recursively verifies the node and its' children
        to see if the SecretVisTree is well-formed. 
        
        AND - Children should all verify and their shares
        combined with bitwise xor should combine to the 
        node's own share
        
        OR - Children should all verify and their shares
        should all be the same as the node's own share
        
        TERM - Nothing to verify
        
        Returns: True or False if the shares verify
        '''
        if node.type == NodeType.TERM:
            return True
        elif node.type == NodeType.OR:
            children_verified = all([self._verify_shares(c) 
                                     for c in node.children])
            all_match = all([node.share == c.share 
                             for c in node.children])
            return children_verified and all_match
        elif node.type == NodeType.AND:
            children_verified = all([self._verify_shares(c) 
                                     for c in node.children])
            children_share = node.children[0].share
            for c in node.children[1:]:
                children_share = byte_xor(children_share, c.share)
            return children_verified and (children_share == node.share)
    
    @staticmethod   
    def _generate_n_random_shares(n, l):
        '''
        Arguments:
        n - the number of random shares to generate
        l - the upper length of the shares to generate (in bytes)
        
        Returns: A list of n random numbers of length l, 
        they are generated using a cryptographic PRNG. 
        '''
        return [Random.get_random_bytes(l) for x in xrange(0, n)]

    def compute_shares(self, secret=None):
        '''
        Arguments:
        secret - the secret to be split into shares 
        
        Modifies the tree and updates the shares accordingly
        '''
        if self.secret is None and secret is None:
            raise ValueError("Secret must be specified")
        secret = self.secret if (not self.secret is None) else secret 
        self._compute_shares(self.root, secret)
        
    def _compute_shares(self, node, share):
        '''
        Arguments:
        node - a VisNode to compute shares for
        share - the share for the current node
        
        Returns: A SecretVisNode with shares computed
        based on the share passed in
        '''
        if node.type == NodeType.TERM:
            node.share = share 
   
        elif node.type == NodeType.OR:
            #Give all the children the same share
            node.share = share
            _ = [self._compute_shares(c, share) 
                 for c in node.children]

        elif node.type == NodeType.AND:
            #Generate random shares for n-1 children and
            #give the last one r1^r2^...^rn-1^m for a share
            node.share = share
            random_shares = SecretVisTree._generate_n_random_shares(
                                            len(node.children)-1,
                                            len(share))
            last_share = share
            for (c,r) in zip(node.children[:-1],random_shares):
                last_share = byte_xor(last_share, r)
                self._compute_shares(c, r)

            self._compute_shares(node.children[-1], last_share)
          
        else:
            #Should never be hitting the empty case
            raise ValueError("Ill formed visibility tree")
                      
class SecretVisTreeEncryptor(object):
    """
    Logic for dealing with secret sharing according to visibility labels, 
    this includes encrypting and decrypting shares:
    
    To encrypt: Build it from an existing visibility tree with a 
       chosen secret to share. Then it is possible to call encrypt 
       on the visibility tree to encrypt the shares under corresponding
       attributes. This functionality is encased in 'compute_shares', and
       'encrypt_shares' respectively
    
    To decrypt: Given an encrypted set of shares and a set of attributes and
       corresponding keys, it parses the expression, decrypts it and combines
       it into the top level share. This functionality is encased in 
       'decrypt_secret_shares'
    """
    
    @staticmethod 
    def encrypt_secret_shares(vis_expr,
                              secret,
                              key_container,
                              leaf_class):  
        """
        Arguments:
        vis_expr - (string) vis_expr to be parsed and shares created
        secret - (bytestring) the secret to be shared
        key_container - (Keytor) key_id for the particular algorithm and key_object to look
        up keys. Throws PKILookupError if the algorithm or attribute
        is not present for that particular user. 
        leaf_class - (Encryption class) class to encrypt the leaves of the vis_tree 
        
        Returns: String of encrypted shares (base64 encoded) formatted
         like a visibility expression
        """
        parser = VisParser()
        tree = parser.parse(vis_expr)
        secret_tree = SecretVisTree(tree.root, 
                                    vis_expr,
                                    secret=secret)
        secret_tree.compute_shares()
        SecretVisTreeEncryptor._encrypt_secret_shares(secret_tree.root,
                                                      key_container,
                                                      leaf_class)
        return secret_tree.print_shares(encrypted=True)
    
    @staticmethod
    def _encrypt_secret_shares(node, key_container, leaf_class):
        '''
        Arugments:
        node - node to be processed
        attribute_key_dict - see main function
        
        Side-effect: Share in node is encrypted
        '''
        if node.type == NodeType.TERM:
            (key, version) = key_container.key_object.get_current_attribute_key(key_container.key_id,
                                                                                node.attribute)
            ciphertext = leaf_class.encrypt(str(node.share), key) 
            node.encrypted_share = base64.b64encode(ciphertext)+'ver'+str(version)
        else: 
            for c in node.children:
                SecretVisTreeEncryptor._encrypt_secret_shares(c,
                                                              key_container,
                                                              leaf_class)
                
      
    @staticmethod  
    def decrypt_secret_shares(vis_expression,
                              share_expression,
                              key_container,
                              leaf_class):
        """
        Arguments:
        vis_expression - the underlying visibility expression,
            this is used to extract attributes to map to keys
        share_expression - the encrypted shares structured in 
            the same way as the visibility label
        key - key_id for the particular algorithm and key_object to look
        up keys. Throws PKILookupError if the algorithm or attribute
        is not present for that particular user. 
        leaf_class - class to encrypt the leaves of the vis_tree 
            
        Returns: the top level secret share made by combining all 
        the necessary shares decrypted. If it is not possible 
        to satisfy the vis_expression with the given terms 
        (the ones present in the attribute_key_dict) None is returned.
        """
        
        visparser = VisParser()
        
        vistree = visparser.parse(vis_expression)
        #NB: in this share tree, start and end in nodes represent the 
        #start and end for the share expression, not the visibility expression
        #as they would when one is encrypting
        shareparser = SecretVisParser()
        share_tree = shareparser.parse(share_expression)
        share_tree.set_attributes(vistree)
        (match, opt_share_tree, keys) = share_tree.optimal_decryption_tree(key_container)
        if not match:
            return None
        
        SecretVisTreeEncryptor._decrypt_secret_shares(opt_share_tree.root, 
                                                      keys,
                                                      leaf_class)
        return opt_share_tree.root.share
    
    @staticmethod
    def _decrypt_secret_shares(node, keys, leaf_class):
        '''
        Arguments: 
        node - top level node to be decrypt and combine the shares
        keys - dictionary of keys indexed by attribute
        leaf-class - encryption class for the leaves 
        
        Returns: The node with its share decrypted and reassembled
        as also all of its children
        
        '''
        if node.type == NodeType.TERM:
            key = keys[node.attribute]
            ciphertext = base64.b64decode(node.encrypted_share.rsplit('ver',1)[0])
            node.share = leaf_class.decrypt(ciphertext, key)
        elif node.type == NodeType.AND:
            _ = [SecretVisTreeEncryptor._decrypt_secret_shares(c, keys, leaf_class)
                 for c in node.children]
            
            children_share = node.children[0].share
            for c in node.children[1:]:
                children_share = byte_xor(children_share, c.share)
            node.share = children_share
            
        elif node.type == NodeType.OR:
            _ = [SecretVisTreeEncryptor._decrypt_secret_shares(c, keys, leaf_class)
                 for c in node.children]
            node.share = node.children[0].share
        else:
            #Should never be hitting the empty case
            raise ValueError("Ill formed visibility tree")
        
        
class SecretVisParser(VisParser):
    
    #Helper functions for parse
    def _processTerm(self, start, end, node_expr, expression):
        """
        Arguments:
            start - start of the term
            end - end of the term
            node_expr - Existing term node or None
            expression - the overall expression 
            
        Returns: Processed term node; if expr existed, it returns 
          the existing node, otherwise creates a new SecretVisNode for
          the term
        """
        if start != end:
            if node_expr is not None:
                raise VisibilityFormatException("expression %s needs to be | or &" % (expression))
            node = SecretVisNode(start=start, end=end, type=NodeType.TERM)
            node.encrypted_share = node.getTerm(expression)
            return node 
        
        if node_expr is None:
            raise VisibilityFormatException("empty term %s" % (expression))
        return node_expr
    
    def _getTreeType(self, node, expression):
        return SecretVisTree(node, expression)
    
    def _create_node(self, start, type):
        return SecretVisNode(start=start, type=type)
        
                
                
                
        
    
    
    
    
