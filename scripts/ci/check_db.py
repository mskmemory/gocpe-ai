"""Apply design DDL and exercise constraints in an isolated, disposable schema."""
import os
from pathlib import Path
import uuid
import psycopg
from psycopg import sql

if os.environ.get('CI_DB_DISPOSABLE') != '1':
    raise SystemExit('Set CI_DB_DISPOSABLE=1 only for a disposable local/CI database')
schema = 'ci_' + uuid.uuid4().hex
conn = psycopg.connect(os.environ['DATABASE_URL'], autocommit=True)
created = False


def rejects(statement, exception):
    try:
        with conn.transaction():
            conn.execute(statement)
    except exception:
        return
    raise AssertionError('Expected constraint rejection: ' + exception.__name__)


try:
    conn.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
    created = True
    conn.execute(sql.SQL('SET search_path TO {}').format(sql.Identifier(schema)))
    conn.execute(Path('db/schema.sql').read_text())
    job = '00000000-0000-0000-0000-000000000001'
    conn.execute("""INSERT INTO resolution_jobs
      (id,owner_id,status,provider,model,options,input_kind,input_document,
       input_sha256,config_sha256,run_metadata,total,expires_at)
      VALUES (%s,'ci','queued','openai','fixture','{}','packages','{}',
       %s,%s,'{}',1,now()+interval '1 day')""", (job, 'a'*64, 'b'*64))
    conn.execute("INSERT INTO resolution_components VALUES (%s,'c1',0,'','{}','{}','pending','[]')", (job,))
    conn.execute("INSERT INTO resolution_targets VALUES (%s,'c1','purl','unresolved','[]','{}')", (job,))
    rejects("UPDATE resolution_jobs SET processed=2", psycopg.errors.CheckViolation)
    rejects("UPDATE resolution_jobs SET status='completed'", psycopg.errors.CheckViolation)
    rejects("""INSERT INTO resolution_components VALUES
      ('00000000-0000-0000-0000-000000000099','c2',0,'','{}','{}','pending','[]')""",
      psycopg.errors.ForeignKeyViolation)
    conn.execute("""INSERT INTO resolution_candidates
      (id,job_id,component_id,target,rank,value,origin,scope,verification_status,
       identity_status,version_status,verification,identity_detail)
      VALUES ('00000000-0000-0000-0000-000000000002',%s,'c1','purl',1,
       'pkg:npm/example','ai','package','no_evidence','plausible','unknown','{}','{}')""", (job,))
    rejects('UPDATE resolution_candidates SET selected=true', psycopg.errors.CheckViolation)
    conn.execute("UPDATE resolution_candidates SET verification_status='confirmed',identity_status='strong',selected=true")
    rejects("UPDATE resolution_candidates SET scope='version'", psycopg.errors.CheckViolation)
    conn.execute("INSERT INTO idempotency_keys VALUES ('ci','key',%s,%s,now()+interval '1 hour')", ('a'*64,job))
    rejects("""INSERT INTO idempotency_keys SELECT * FROM idempotency_keys""", psycopg.errors.UniqueViolation)
    conn.execute('DELETE FROM resolution_jobs WHERE id=%s', (job,))
    for table in ('resolution_components','resolution_targets','resolution_candidates','idempotency_keys'):
        assert conn.execute(sql.SQL('SELECT count(*) FROM {}').format(sql.Identifier(table))).fetchone()[0] == 0
    print('DDL, foreign keys, uniqueness, selection/version checks and cascade deletion passed')
finally:
    conn.execute('ROLLBACK')
    if created:
        conn.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))
    conn.close()
