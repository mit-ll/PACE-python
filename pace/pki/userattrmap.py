## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: ES
##  Description: User-to-attribute map interface and simple implementation
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  3 Sep 2015   ES    Original file
## **************

from abc import ABCMeta, abstractmethod

class AbstractUserAttrMap(object):
    """ Abstract interface for fetching attributes for a given user.
    """
    
    __metaclass__ = ABCMeta

    @abstractmethod
    def attributes_by_user(self, userid):
        """ Returns a list of the attributes the given user has.

            Arguments:
            userid (string) - the ID of the user whose attributes to retrieve

            Returns:
            [string] - a (potentially empty) list of the attributes that the 
                given user has 
        """
        pass

    def delete_attr(self, userid, attr):
        """ Deletes an attribute from the list of attributes of a given user.
            Used in key revocation. If the user does not already have the 
            attribute, this function does nothing.

            Arguments:
            userid (string) - the ID of the user whose attribute to delete
            attr (string) - the attribute to delete from the user's list
        """
        pass

class LocalUserAttrMap(AbstractUserAttrMap):
    """ A simple implementation of a user-to-attribute map that references a
        dictionary passed in at initialization.

        Fields:
        user_attr_dict ({string -> [string]}) - a dictionary mapping each user 
            ID to a list of attributes
    """

    def __init__(self, user_attr_dict):
        """ Initializes the user-to-attribute map with a provided dictionary.
        """
        #Create a fresh copy of the provided dictionary to prevent aliasing 
        #issues
        self.user_attr_dict = {}
        for key, val in user_attr_dict.iteritems():
            self.user_attr_dict[key] = list(val)

    def attributes_by_user(self, userid):
        """ Returns a list of the attributes the given user has.

            Arguments:
            userid (string) - the ID of the user whose attributes to retrieve

            Returns:
            [string] - a (potentially empty) list of the attributes that the 
                given user has
        """
        try:
            return [attr for attr in self.user_attr_dict[userid]]
        except KeyError:
            return []

    def delete_attr(self, userid, attr):
        """ Deletes an attribute from the list of attributes of a given user.
            Used in key revocation. If the user does not already have the 
            attribute, this function does nothing.

            Arguments:
            userid (string) - the ID of the user whose attribute to delete
            attr (string) - the attribute to delete from the user's list
        """
        try:
            self.user_attr_dict[userid].remove(attr)
        except ValueError:
            pass
        except KeyError:
            pass
