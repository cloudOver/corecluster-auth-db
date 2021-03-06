"""
Copyright (C) 2014-2017 cloudover.io ltd.
This file is part of the CloudOver.org project

Licensee holding a valid commercial license for this software may
use it in accordance with the terms of the license agreement
between cloudover.io ltd. and the licensee.

Alternatively you may use this software under following terms of
GNU Affero GPL v3 license:

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version. For details contact
with the cloudover.io company: https://cloudover.io/


This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.


You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""


from corecluster.models.core import Token, User, Node
from corecluster.utils.exception import CoreException
from corenetwork.utils.logger import log
from django.db.models import Q
import datetime
import hashlib
import time
import random

def auth_token(data, function_name):
    """ Authenticate by token """
    user_id = None
    if not 'token' in data.keys():
        raise CoreException('missing_token')

    try:
        token_id,method,salt,token_hash = data['token'].split('-')
    except:
        raise CoreException('token_malformed')

    try:
        token = Token.objects.get(id=token_id)
    except:
        time.sleep(random.random()*5)
        raise CoreException('token_not_found')

    if method == 'sha256':
        if hashlib.sha256(salt + token.token).hexdigest() != token_hash:
            raise CoreException('auth_failed')
    elif method == 'sha512':
        log(hashlib.sha512(salt + token.token).hexdigest())
        log(token_hash)
        if hashlib.sha512(salt + token.token).hexdigest() != token_hash:
            raise CoreException('auth_failed')
    else:
        raise CoreException('auth_hash_not_supported')

    del data['token']
    if token.valid_to < datetime.datetime.now():
        raise CoreException('token_expired')

    fname = function_name.replace('.', '/')
    if fname[0] == '/':
        fname = fname[1:]
    if fname[-1] == '/':
        fname = fname[:-1]

    # TODO: Cache function list (permission table) in memory instead of db
    if not token.ignore_permissions and not token.permissions.filter(function=fname).exists():
        raise Exception('token_permission')

    if not token.user.group.role.permissions.filter(function=fname).exists():
        if not token.user.role.permissions.filter(function=fname).exists():
            raise Exception('user_permission')

    return token.user, data


def auth_password(data, function_name):
    """ Authenticate user by password """
    if not 'login' in data.keys():
        raise Exception('missing_login')

    if not 'pw_hash' in data.keys():
        raise Exception('missing_password_hash')

    user = User.get_login(data['login'], data['pw_hash'])
    del data['login']
    del data['pw_hash']

    return user, data


def auth_node(data, remote_host):
    """
    Authenticate node by its auth_hash and installation_id. Auth hash is combination of installation ID and auth
    seed passed to /ci/node/register/ at first time
    """
    try:
        node = Node.objects.get(installation_id=data['installation_id'])
    except Exception as e:
        raise CoreException('node_not_found')

    try:
        node.check_auth(data['auth_hash'])
    except Exception as e:
        raise CoreException('node_not_authenticated')

    del data['installation_id']
    del data['auth_hash']
    node.comment = '%s\nAuthenticated from IP %s\n' % (node.comment, remote_host)
    node.save()
    return node, data


def get_object(object_class, user_id, object_id):
    """
    Get object from database with respect to access and ownership
    :param object_class: Class of object
    :param user_id: User's id who is trying to get object
    :param object_id: Object's id
    """
    try:
        obj = object_class.objects.get(id=object_id)
    except Exception:
        raise CoreException('object_not_found')

    if obj.user.id == user_id:
        return obj

    if obj.access == 'public':
        return obj

    if obj.access == 'group':
        from corecluster.models.core.user import User
        user = User.objects.get(id=user_id)
        if obj.user.group == user.group:
            return obj
        if obj.group is not None and obj.group == user.group:
            return obj

    raise CoreException('object_permission')


def get_list(object_class, user_id, criteria={'id__isnull': False}, exclude={'id__isnull': True}, order_by=['id']):
    """
    Get list of objects (optionaly filtered by criteria) with respect to ownership and group access
    :param user_id: id of owner
    :param criteria: django dictionary with criteria (e.g. name="abcd")
    :param order_by: python list with field names, which will sort objects. By default this is id
    :return: Queryset or empty python's list
    """
    from corecluster.models.core.user import User
    user = User.objects.get(id=user_id)
    try:
        user_obj = object_class.objects.filter(user_id=user_id).filter(**criteria).exclude(**exclude).order_by(*order_by)
        group_obj = object_class.objects.filter(Q(user__group=user.group), Q(access='group')).filter(**criteria).exclude(**exclude).order_by(*order_by)
        public_obj = object_class.objects.filter(access='public').filter(**criteria).exclude(**exclude).order_by(*order_by)

        return user_obj | group_obj | public_obj
    except:
        return []
