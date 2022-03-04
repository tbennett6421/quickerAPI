#!/usr/bin/env python3

from __future__ import print_function
from __future__ import absolute_import

__code_version__ = 'v1.0.0'

## Standard Libraries
from pprint import pprint
# import pickle
# import hashlib
# try:
#     import jsonpickle as json
# except ImportError:
#     import json

"""
 BaseObject provides a template of useful methods for all classes to inherit
"""
class BaseObject(object):

    def __init__(self, state=None):
        self.is_valid = False
        if state is None:
            self.tracking_state = False
        else:
            if isinstance(state, State):
                self.tracking_state = True
                self.pg_state = state
            else:
                raise TypeError("state argument was not instance of <State>")

    def keys(self):
        return list(self.meta().keys())

    def vals(self):
        return list(self.meta().values())

    def values(self):
        return self.vals()

    def meta(self):
        try:
            return self.__dict__
        except:
            raise

    def ready(self, throw=False, message=None):
        if throw:
            if not self.is_valid:
                if message is None:
                    raise ValueError("Unable to successfully instantiate object of class::"+self.__class__.__name__)
                else:
                    raise ValueError(message)
            else:
                return self.is_valid
        else:
            return self.is_valid

    # def frozen(self):
    #     try:
    #         return frozenset(self.meta())
    #     except Exception as e:
    #         return {'frozen_error': e}

    # def marshall(self):
    #     try:
    #         return json.dumps(self.__dict__)
    #     except Exception as e:
    #         return {'marshall_error': e}

    # def serialize(self):
    #     try:
    #         return pickle.dumps(self.__dict__)
    #     except Exception as e:
    #         return {'serialize_error': e}

    # def dump(self):
    #     try:
    #         j = self.marshall().encode('utf-8')
    #         jd = hashlib.sha1(j).hexdigest()
    #         f = repr(self.frozen()).encode('utf-8')
    #         fd = hashlib.sha1(f).hexdigest()
    #         p = self.serialize()
    #         pd = hashlib.sha1(p).hexdigest()
    #         return {
    #             "json": j,
    #             "json_digest": jd,
    #             "json_digest_method": "SHA1",
    #             "frozen": f,
    #             "frozen_digest": fd,
    #             "frozen_digest_method": "SHA1",
    #             "pickle": p,
    #             "pickle_digest": pd,
    #             "pickle_digest_method": "SHA1"
    #         }
    #     except:
    #         raise

    def getProp(self, prop=None):
        if prop not in self.keys():
            raise ValueError(str(prop)+" is not a valid property to get()")
        else:
            return getattr(self, prop)

    def getParam(self, param=None):
        return self.getProp(param)

"""
 Borg provides a way to implement trivial Singletons, rather then sharing an
 object the borg provides any number of objects with the same internal data
"""
class Borg(BaseObject):
    __shared_state = {}
    def __init__(self):
        self.__dict__ = self.__shared_state
        ## Call parent init()
        super().__init__()

"""
 This class is designed to store the program state in a fashion to be used via
 multiple modules and provides a singleton-like way to access the state of the program
"""
class State(Borg):
    def __init__(self):
        Borg.__init__(self)
        self.is_valid = True
        self.ready(throw=True)

def demo():
    print("=== Demo ===")

    #region statedemo
    print("--- State() --- ")
    print(">>> obj = State()")
    obj = State()
    print(">>> state.ready()")
    print(obj.ready())
    obj.rgb = [252, 186, 3]
    obj.hex = "#fcba03"
    obj.name = "Gold"
    print(">>> setting attributes on obj")
    pprint(obj.meta())
    print(">>> creating new object of type <class State()> ")
    print(">>> yellow = State()")
    yellow = State()
    print(">>> dumping attributes of new object")
    pprint(yellow.meta())
    print(">>> setting new attributes on obj (yellow=>red)")
    obj.rgb = [255, 0, 0]
    obj.hex = "#ff0000"
    obj.name = "Red"
    print(">>> As a result: all state object old/new will now be red")
    print(">>> dumping attributes of yellow object")
    pprint(yellow.meta())
    #endregion statedemo
    print()
    #region baseobject
    print("--- BaseObject() --- ")
    print(">>> obj = BaseObject()")
    obj = BaseObject()
    attrs = []
    for m in dir(obj):
        if "__" not in m:
            attrs.append(m)
    print(attrs)
    print(">>> Calling obj.keys()")
    print(obj.keys())
    print(">>> Calling obj.vals()")
    print(obj.vals())
    print(">>> Calling obj.meta()")
    print(obj.meta())
    print(">>> Calling obj.ready()")
    print(obj.ready())
    print(">>> Calling obj.ready(throw=True)")
    try:
        obj.ready(throw=True)
    except ValueError:
        print("Caught Exception and suppressing")
    #print(">>> Calling obj.dump()")
    #print(obj.dump())
    #endregion baseobject

def main():
    demo()

if __name__=="__main__":
    main()
