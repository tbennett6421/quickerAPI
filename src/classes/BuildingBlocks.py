#!/usr/bin/env python3

from __future__ import print_function
from __future__ import absolute_import

__code_version__ = 'v3.1.1'

## Standard Libraries
from pprint import pprint

## Modules
try:
    from classes.Exceptions import ValidationFailedError
except ImportError:
    from Exceptions import ValidationFailedError

"""
    BaseObject provides a template of useful methods for all classes to inherit
"""
class BaseObject(object):

    def __init__(self, state=None, loglevel='INFO'):

        #region: debugging handler
        if loglevel == "DEBUG":
            try:
                import debugpy
                debugpy.listen(5678)
                print("Waiting for debugger attach")
                debugpy.wait_for_client()
                debugpy.breakpoint()
                print('break on this line')
            except ImportError:
                pass
        #endregion: debugging handler

        self.is_valid = False
        if state is None:
            self.tracking_state = False
        else:
            if isinstance(state, State):
                self.tracking_state = True
                self.pg_state = state
            else:
                raise TypeError("state argument was not instance of <State>")

    def AnyElementIsNone(self, lst):
        """
            Check a provided list if any element is None; Used for validation checks
            Return:
                True is anything in the list is None
                False if all checks proceeded successfully
        """
        try:
            for k in lst:
                attr = getattr(self, k)
                if attr is None:
                    return True
            return False
        except KeyError as e:
            print(e)
            return True
        except Exception as e:
            raise e

    def keys(self):
        return list(self.meta().keys())

    def meta(self):
        try:
            return self.__dict__
        except:
            raise

    def ready(self, throw=False, message=None):
        if throw:
            if not self.is_valid:
                if message is None:
                    raise ValidationFailedError("Unable to successfully instantiate object of class::"+self.__class__.__name__)
                else:
                    raise ValidationFailedError(message)
            else:
                return self.is_valid
        else:
            return self.is_valid

    def vals(self):
        return list(self.meta().values())

    def values(self):
        return self.vals()

    def getProp(self, prop=None):
        try:
            gs = self.gs_fn
        except AttributeError:
            self.gs_fn = None
        except Exception as e:
            print(e.__name__)
            print(e)
            raise e

        if prop not in self.keys():
            # do we have access to a gs_fn?
            if self.gs_fn is not None:
                gs = self.gs_fn[prop]
                get = gs[0]
                return get()
            else:
                raise ValueError(str(prop)+" is not a valid property to get()")
        else:
            return getattr(self, prop)

    def getParam(self, param=None):
        return self.getProp(param)

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

"""
    Borg provides a way to implement trivial Singletons, rather than sharing an
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
