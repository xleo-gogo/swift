import boto3
import json
import swiftclient
from swiftclient.exceptions import ClientException
from swiftclient.service import SwiftService
from swiftclient.client import Connection
import swiftclient.service

g_endpoint_url = "http://127.0.0.1:8000"
g_auth_url = "http://127.0.0.1:8000/auth"
#g_auth_url = "http://172.10.32.234:8080/auth"
#g_swift_user ='tt$gg:s1'
#g_swift_secret = 'nui0xlMstDDe1QJRAkQwEUOBBcHohi2ym9cq3Ic6'
g_swift_user ='test:tester'
g_swift_secret = 'testing'

g_s3 = boto3.client('s3', endpoint_url=g_endpoint_url, aws_access_key_id="0555b35654ad1656d804",
                    aws_secret_access_key="h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q==")

def list_obj_versions():
    try:
        #resp = s3.list_objects(Bucket="tb1", Prefix="Makefile")
        resp = g_s3.get_bucket_versioning(Bucket='tb1')
        print(resp)
        resp = g_s3.list_object_versions(Bucket="tb1", Prefix="Makefile")
        for ver in resp["Versions"]:
            print(ver["Key"] + ":" + ver["VersionId"] + ":" +
                  str(ver["LastModified"]) + "islatest:" + str(ver['IsLatest']))
        if  resp.get('DeleteMarkers'):
            print("delete markers")
            for ver in resp['DeleteMarkers']:
                print(ver["Key"] + ":" + ver["VersionId"] + ":" +
                      str(ver["LastModified"]) + "islatest:" + str(ver['IsLatest']))
    except Exception as e:
        print(e)


def enable_version(bucket, enable_swift=True, enable_s3=False):
    if enable_s3:
        try:
            # 'Status': 'Enabled'|'Suspended'
            ret = g_s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={'Status': 'Suspended'})
            print(ret)
        except Exception as e:
            print(e)
    if enable_swift:
        with SwiftService() as swift:
            try:
                resp = swift.post(container=bucket, options={'header': ['X-Versions-Location: archive']})
                print(resp)
            except ClientException as e:
                print(e)


def set_account_acl():
    cnn = Connection(authurl='http://127.0.0.1:8000/auth', user='lily:s1', 
                     key='KyaL9f6ii1jzIRAkR3UvUBVCm8XJNAsYHnNHsolR')
    try:
        acl = {'read-only':['.r:*'], 'read-write': ['yy', "xx"]}
        acl_str = json.dumps(acl)
        cnn.post_account(headers={'x-account-access-control': acl_str})
    except ClientException as e:
        print(e)
    cnn.close()


def get_account_acl():
    cnn = Connection(authurl='http://127.0.0.1:8000/auth', user='lily:s1', 
                     key='KyaL9f6ii1jzIRAkR3UvUBVCm8XJNAsYHnNHsolR')
    try:
        resp = cnn.head_account()
        acl = resp.get('x-account-access-control')
        if acl is not None:
            acl_json = json.loads(acl)
            print(acl_json.get('read-only', ''))
            print(acl_json.get('read-write', ''))
            print(acl_json.get('admin', ''))
    except ClientException as e:
        print(e)
    cnn.close()
      
  
def view_version_objs():
    with SwiftService() as swift:
        resp = swift.list('archive', options={'prefix':'008Makefile'})
        for list_part in resp:
            for item in list_part['listing']:
                print(item)         


def list_container():
    cnn = Connection(authurl= g_auth_url, user=g_swift_user, key=g_swift_secret)
    try:
        resp = cnn.get_account()
        print(resp)
    except ClientException as e:
        print(e)
    cnn.close()


def create_container():
    cnn = Connection(authurl= g_auth_url, user=g_swift_user, key=g_swift_secret)
    try:
        cnn.put_container(container='bk1',
                          headers={'X-Container-Read': '.r:*',           # ACL
                                   'X-Container-Write': 'jack',           # ACL
                                   'X-Versions-Location': 'backup',       # 开启容器多版本，并指定备份容器
                                   'X-Storage-Policy': 'default-placement',# 容器的存储策略
                                   'X-Object-Storage-Class': 'STANDARD'})  # 容器的存储类，不指定就用存储策略默认的存储类
    except ClientException as e:
        print(e)
    cnn.close()


def del_container():
    cnn = Connection(authurl= g_auth_url, user=g_swift_user, key=g_swift_secret)
    try:
        cnn.delete_container('bk1')
    except ClientException as e:
        print(e)
    cnn.close()



def set_container_acl():
    cnn = Connection(authurl='http://127.0.0.1:8000/auth', user='lily:s1', 
                     key='KyaL9f6ii1jzIRAkR3UvUBVCm8XJNAsYHnNHsolR')
    try:
        cnn.post_container(container='bk3',
                          headers={'X-Container-Read': 'yy,kk',
                                   'X-Container-Write': 'kk',
                                   'X-Versions-Location': 'backup'})
    except ClientException as e:
        print(e)
    cnn.close()


def stat_container():
    cnn = Connection(authurl='http://127.0.0.1:8000/auth', user='lily:s1', 
                     key='KyaL9f6ii1jzIRAkR3UvUBVCm8XJNAsYHnNHsolR')
    try:
        resp = cnn.head_container(container='bk3')
        print(resp)
    except ClientException as e:
        print(e)
    cnn.close()



def list_objects():
    cnn = Connection(authurl=g_auth_url, user='test:tester', key='testing')
    try:
        resp = cnn.get_container('tbb')
        print(resp)
    except ClientException as e:
        print(e)
    cnn.close()


def list_versiond_objects():
    cnn = Connection(authurl=g_auth_url, user=g_swift_user, key=g_swift_secret)
    try:
        object_name = 't1'
        resp = cnn.head_container(container='bucket9')
        archive_container = resp.get('x-versions-location','')
        if archive_container != '':
            archive_prefix = '{:03x}{}/'.format(len(object_name), object_name)
            headrs, objs = cnn.get_container(container=archive_container, prefix=archive_prefix)
            print(objs)
    except ClientException as e:
        print(e)
    cnn.close()


def upload_obj():
    cnn = swiftclient.client.Connection(authurl=g_auth_url, user='uu:s1', key='x')
    try:
        cnn.put_object(container='bk1', obj='hello.txt', contents='hello world', 
                       headers={'X-OBJECT-STORAGE-CLASS':'STANDARD'})
    except ClientException as e:
        print(e)


def download_obj():
    cnn = swiftclient.client.Connection(authurl=g_auth_url, user='uu:s1', key='x')
    try:
        headers, content = cnn.get_object(container='bk1', obj='hello.txt')
        print(headers)
        print(content)
    except ClientException as e:
        print(e)


def delete_obj():
    cnn = swiftclient.client.Connection(authurl=g_auth_url, user='uu:s1', key='x')
    try:
        cnn.delete_object(container='bk1', obj='hello.txt')
    except ClientException as e:
        print(e)


def add_account_meta():
    cnn = Connection(authurl='http://127.0.0.1:8000/auth', user='lily:s1', 
                     key='KyaL9f6ii1jzIRAkR3UvUBVCm8XJNAsYHnNHsolR')
    try:
        cnn.post_account(headers={'X-Account-Meta-author_Y':'yecw',
                                  'X-Account-Meta-age':'1year'})
    except ClientException as e:
        print(e)


def del_account_meta():
    cnn = Connection(authurl='http://127.0.0.1:8000/auth', user='lily:s1', 
                     key='KyaL9f6ii1jzIRAkR3UvUBVCm8XJNAsYHnNHsolR')
    try:
        cnn.post_account(headers={'X-Account-Meta-age':''})
    except ClientException as e:
        print(e)


def get_account_meta():
    cnn = Connection(authurl='http://127.0.0.1:8000/auth', user='lily:s1', 
                     key='KyaL9f6ii1jzIRAkR3UvUBVCm8XJNAsYHnNHsolR')
    try:
        headers = cnn.head_account()
        for k, v in headers.items():
            if 'x-account-meta-' in k:
                print('{} : {}'.format(k, v))
    except ClientException as e:
        print(e)


def add_container_meta():
    cnn = Connection(authurl='http://127.0.0.1:8000/auth', user='lily:s1',
                     key='KyaL9f6ii1jzIRAkR3UvUBVCm8XJNAsYHnNHsolR')
    try:
        cnn.post_container(container='bk2', headers={'X-Container-Meta-Author': 'yecw',
                                                     'X-Container-Meta-year': '2012',
                                                     'X-Container-Meta-place': 'cd'})
    except ClientException as e:
        print(e)


def del_container_meta():
    cnn = Connection(authurl='http://127.0.0.1:8000/auth', user='lily:s1',
                     key='KyaL9f6ii1jzIRAkR3UvUBVCm8XJNAsYHnNHsolR')
    try:
        cnn.post_container(container='bk2', headers={
                           'X-Container-Meta-year': ''})
    except ClientException as e:
        print(e)


def get_container_meta():
    cnn = Connection(authurl='http://127.0.0.1:8000/auth', user='lily:s1',
                     key='KyaL9f6ii1jzIRAkR3UvUBVCm8XJNAsYHnNHsolR')
    try:
        headers = cnn.head_container(container='bk2')
        for k, v in headers.items():
            if 'x-container-meta-' in k:
                print('{} : {}'.format(k, v))
    except ClientException as e:
        print(e)

def add_obj_tag():
    cnn = Connection(authurl='http://127.0.0.1:8000/auth', user='lily:s1',
                     key='KyaL9f6ii1jzIRAkR3UvUBVCm8XJNAsYHnNHsolR')
    try:
        cnn.post_object(container='bk2', obj='g.txt',
                        headers={'X-Object-Meta-AuThor': 'YeCW',
                                 'X-Object-Meta-X_Z': 'KK',
                                 'X-Object-Meta-age': ''})
    except ClientException as e:
        print(e)


def add_obj_tag2():
    cnn = Connection(authurl='http://127.0.0.1:8000/auth', user='lily:s1',
                     key='KyaL9f6ii1jzIRAkR3UvUBVCm8XJNAsYHnNHsolR')
    try:
        cnn.post_object(container='bk2', obj='g.txt',
                        headers={'X-Delete-After': 100})
    except ClientException as e:
        print(e)


def get_obj_tag():
    cnn = Connection(authurl='http://127.0.0.1:8000/auth', user='lily:s1',
                     key='KyaL9f6ii1jzIRAkR3UvUBVCm8XJNAsYHnNHsolR')
    try:
        resp = cnn.head_object(container='bk2', obj='g.txt')
        for k,v in resp.items():
            if 'x-object-meta-' in k:
                print('{} : {}'.format(k, v))
    except ClientException as e:
        print(e)
    cnn.close()



def bucket_policy():
    response = g_s3.put_bucket_policy(Bucket='bk1',
                                      Policy='{"Version": "2012-10-17", "Statement": [{ "Sid": "id-1","Effect": "Allow","Principal": {"AWS": "arn:aws:iam::t1:user/tt"}, "Action": [ "s3:PutObject","s3:PutObjectAcl"], "Resource": ["arn:aws:s3:::acl3/*" ] } ]}',)
    print(response)


def test_put_object_to_others_container():
    c = 'bbx20'
    o = 'hello'
    try:
        cnn1 = Connection(authurl='http://127.0.0.1:8000/auth', user='test:tester', key='testing')
        cnn1.put_container(container=c, headers={'X-Container-Write': 'test2'})
        cnn2 = Connection(authurl='http://127.0.0.1:8000/auth', user='test2:tester2', key='testing2')
        cnn2.put_object(container=c, obj=o, contents="hello")
        #resp = cnn1.post_container(container=c, headers={'X-Container-Read': 'test'})
        resp = cnn1.head_container(container=c)
        resp = cnn1.get_object(container=c, obj=o)
        print(resp)
    except Exception  as e:
        print(e)


def test_versioned_container():
    cnn = Connection(authurl= g_auth_url, user=g_swift_user, key=g_swift_secret)
    try:
        cnn.put_container(container='bk1',
                          headers={'X-Container-Read': '.r:*',           # ACL
                                   'X-Container-Write': 'jack',           # ACL
                                   'X-Versions-Location': 'backup',       # 开启容器多版本，并指定备份容器
                                   'X-Storage-Policy': 'default-placement',# 容器的存储策略
                                   'X-Object-Storage-Class': 'STANDARD'})  # 容器的存储类，不指定就用存储策略默认的存储类
    except ClientException as e:
        print(e)
    cnn.close()

if __name__ == '__main__':
    cnn = Connection(authurl='http://127.0.0.1:8000/auth', user='test:tester', 
                     key='testing')
    try:
        headers = cnn.head_account()
        for k, v in headers.items():
            if 'x-account-meta-' in k:
                print('{} : {}'.format(k, v))
    except ClientException as e:
        print(e)
    exit()
   
    list_versiond_objects()
     
    #enable_version('bk1', False, True)
    s3 = boto3.client('s3', endpoint_url=g_endpoint_url)
    #resp = s3.get_bucket_versioning(Bucket='bk1')
    #print(resp.get('Status', '未设置Version'))
   
 
    #enable_version('sba', True, True)
  
    #resp=s3.put_bucket_acl(Bucket='sba', GrantRead='id=tom')
    #resp = s3.get_bucket_acl(Bucket="sba")

 
    
    #resp = swift.list('sba', options={'prefix':'t.txt', 'versions': True})
    #for i in resp:
    #    print(i)
   

    resp = s3.list_object_versions(Bucket="sba", Prefix='t.txt')
    for i in resp['Versions']:
        print(i['VersionId'])
    last = resp['Versions'][0]['VersionId']
    resp = s3.download_file(
        "sba", "t.txt", "/home/yecw/g.txt",
        ExtraArgs={"VersionId": last}
    )
    print(resp)
