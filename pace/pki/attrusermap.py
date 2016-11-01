## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: CAS
##  Description: Attribute-to-user map interface & implementations
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  24 Aug 2015  CAS   Original file
##  28 Aug 2015  CAS   Changed file & object name
## **************

from abc import ABCMeta, abstractmethod

class AbstractAttrUserMap(object):
    """ Abstract interface for fetching attribute-user mappings
        (i.e. for an Accumulo instance). Can be standalone or folded in
        to some other bit of infrastructure, such as a keystore. Assumes
        any updates to the contents of said store are updated elsewhere,
        as there is no functionality to add or delete a user in this API.
    """
    
    __metaclass__ = ABCMeta

    @abstractmethod
    def users_by_attribute(self, attr):
        """ Return the list of all users who are currently authorized to
            read data with the given attribute.

            Arguments:

            attr : string - the attribute to query

            Returns:

            users : [string] - a (potentially empty) list of usernames
                    (as strings) that are all authorized to have the given
                    attribute `attr`
        """
        pass

    @abstractmethod
    def delete_user(self, attr, user):
        """ Delete a user from the list of users with a given attribute.
            Used for key revocation. If the class implementing this
            interface is a wrapper around a separate service that is
            already taking attribute revocations into account, this may
            just be implemented with `pass`.

            Arguments:

            attr : string - the attribute to delete a user from
            user : string - the user to be deleted from attr
        """
        pass


class LocalAttrUserMap(AbstractAttrUserMap):
    """ Simple attribute store that references a static dictionary passed
        in at initialization.

        Fields:

        attr_dict : {string -> [string]} - a dictionary mapping attribute
                    strings to lists of users.
    """
    def __init__(self, attr_dict):
        """ Initialize the attribute-to-user map with a provided dictionary.
        """
        #Create a fresh copy of the provided dictionary to prevent aliasing 
        #issues
        self.attr_dict = {}
        for key, val in attr_dict.iteritems():
            self.attr_dict[key] = list(val)

    def users_by_attribute(self, attr):
        """ Return the list of all users who are currently authorized to
            read data with the given attribute.

            Arguments:

            attr : string - the attribute to query

            Returns:

            users : [string] - a (potentially empty) list of usernames
                    (as strings) that are all authorized to have the given
                    attribute `attr`
        """
        try:
            newlist = [x for x in self.attr_dict[attr]]
            return newlist
        except KeyError:
            return []

    def delete_user(self, attr, user):
        """ Delete a user from the list of users with a given attribute.
            Used for key revocation.

            Arguments:

            attr : string - the attribute to delete a user from
            user : string - the user to be deleted from attr
        """
        try:
            self.attr_dict[attr].remove(user)
        except ValueError:
            pass
        except KeyError:
            pass
