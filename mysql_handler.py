import mysql.connector
from pathlib import Path

def connect():
    try:
        global cnx
        cnx = mysql.connector.connect(
            host="localhost",
            user="dynodelc_tp-main",
            passwd=Path('../priv/sql-tp-pass.txt').read_text(),
            database="dynodelc_tutorialpaths"
        )
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


def execute(sql, commit, multiple, *toopool):
    try:
        res = connect()
        cursor = cnx.cursor()
        ret = cursor.execute(sql, toopool, multi=multiple)
        if commit:
            cnx.commit()
        if multiple:
            for reta in ret:
                try:
                    print(reta)
                except Exception as e:
                    return {"success": False, "error": str(e)}
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        cursor.close()
        cnx.close()


def fetchone(sql, *toopool):
    try:
        res = connect()
        cursor = cnx.cursor()
        cursor.execute(sql, toopool)
        return {"success": True, "results": cursor.fetchone()}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        cursor.close()
        cnx.close()


def fetchall(sql, *toopool):
    try:
        res = connect()
        cursor = cnx.cursor()
        cursor.execute(sql, toopool)
        return {"success": True, "results": cursor.fetchall()}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        cursor.close()
        cnx.close()
