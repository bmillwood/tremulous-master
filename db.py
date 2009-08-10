def dbconnect(id):
    if id == 'auto':
        try:
            from logsqlite import log_client, log_gamestat, db_id
        except ImportError:
            from logtdb import log_client, log_gamestat, db_id
    elif id == 'sqlite':
        from logsqlite import log_client, log_gamestat, db_id
    elif id == 'tdb':
        from logtdb import log_client, log_gamestat, db_id
    elif id == 'none':
        def disabled_db(*args):
            '''This function is defined and used when the database is disabled
            by configuration options'''
        log_client = log_gamestat = disabled_db
        db_id = 'Not using a database'
    else:
        assert False, 'unhandled config.db option'

    return log_client, log_gamestat, db_id
