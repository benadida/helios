"""
DB Abstraction for PG

Author: ben@adida.net, arjun@arjun.nu
"""

import psycopg2
import psycopg2.extensions
import utils, config
from DBUtils.PooledDB import PooledDB


# do unicode
psycopg2.extensions.register_type(psycopg2.extensions.UNICODE)
pool = PooledDB(psycopg2, port = config.DB_PORT, database = config.DB_NAME, host = config.DB_HOST)

class Context:
    pass
    
default_context = Context()

#
# Thread Safe way to manage context
#
def set_context_function(func):
    DB.get_context = func

# by default, context is just this module
def get_context():
    return default_context

def load():
    ctx = get_context()
    ctx.conn = pool.connection()
    ctx.transact_count = 0
    pass

def unload():
    ctx = get_context()
    del ctx.conn
    pass

def _get_cursor():
    ctx = get_context()
    
    if not hasattr(ctx,'conn'):
        load()
        
    if hasattr(ctx,'cursor'): 
        del ctx.cursor
        
    ctx.cursor = ctx.conn.cursor()
    ctx.cursor.execute('set client_encoding = \'UNICODE\'')
    return ctx.cursor
    
def _cursor_execute(cursor,sql, vars):
    cursor.execute(sql, vars)
    
def _done():
    ctx = get_context()
    if ctx.transact_count == 0:
        ctx.conn.commit()
    
# transactions
def transact():
    ctx = get_context()

    if not hasattr(ctx, 'transact_count'):
      load()
      
    # nested transactions by just waiting for the last commit
    ctx.transact_count += 1

def commit():
    ctx = get_context()
    
    ctx.transact_count -= 1;
    if ctx.transact_count == 0:
        ctx.conn.commit()

def rollback():
    ctx = get_context()

    ctx.conn.rollback()
    
    ctx.transact_count -= 1;
    if ctx.transact_count > 0:
        ctx.transact_count = 0
        raise Exception('cannot roll back an inner transaction, rolling back everything.')

def perform(sql, level=0, extra_vars= None):
    db_cursor = _get_cursor()

    _cursor_execute(db_cursor,sql, utils.parent_vars(level+1,extra_vars))
    _done()

def oneval(sql, level=0):
    singlerow = onerow(sql, level+1)
    if singlerow == None:
        return None

    return singlerow.values()[0]

def onerow(sql, level=0):
    rows= multirow(sql, level+1)
    if len(rows) == 0:
       return None
    return rows[0]

def multirow(sql, level=0, extra_vars = None):
    db_cursor = _get_cursor()
    
    _cursor_execute(db_cursor,sql, utils.parent_vars(level+1, extra_vars))
    rows= db_cursor.fetchall()
    colnames = [t[0] for t in db_cursor.description]  
    dict_rows = [dict(zip(colnames, row)) for row in rows]
    
    # if we'er not in a transaction, commit since pyscopg2 opens a transaction on every query
    _done()
    return dict_rows

def dbstr(the_str):
    if type(the_str) == int or type(the_str) == long or type(the_str) == bool:
        return the_str
    return "'"+the_str.replace("'","''").replace("%","%%")+"'"

    
