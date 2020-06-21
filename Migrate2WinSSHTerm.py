__author__ = 'Alex D., P-St'
__version__ = '0.13'

import wx
from anytree import Node, Resolver, ChildResolverError
import base64
from _winreg import *
import configparser
from xml.sax.saxutils import escape
import xml.etree.ElementTree as ET
import os
import urllib
import codecs
import sys
import StringIO

class Migrate2WinSSHTerm(wx.Frame):
    def saveSessionData(self, node=None, name=None, username=None, privateKey=None, hostname=None, port=None):
        Node(escape(name),
            parent=node,
            type="Connection",
            username=escape(username),
            pubkey=escape(privateKey),
            hostname=escape(hostname),
            port=escape(port)
            )

    def writeNode(self, node=None, xml=None):
        if node.type == 'Container':
            xml.write("<Node Name='%s' Type='Container' Expanded='True'>\n" % escape(base64.b64decode(node.name)))
            for n in node.children:
                self.writeNode(n, xml)
            xml.write('</Node>\n')
        if node.type == 'Connection':
            node_data = '''<Node \
Name='%s' \
Type='Connection' \
Descr='' \
Username='%s' \
Password='' \
PrivateKey='%s' \
Hostname='%s' \
Port='%s' />\n''' % (node.name, node.username, node.pubkey, node.hostname, node.port)
            xml.write(node_data)

    def get_con_xml_path(self):
        style = wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT
        dialog = wx.FileDialog(self, message='Save connections.xml',defaultFile='connections.xml', wildcard='connections.xml|connections.xml', style=style)
        if dialog.ShowModal() == wx.ID_OK:
            path = dialog.GetPath()
        else:
            path = None
        dialog.Destroy()
        return path

    def create_xml(self):
        conFile = self.get_con_xml_path()
        if conFile != None:
            xml = codecs.open(conFile, 'w', 'utf-8')
            xml.write("<?xml version='1.0' encoding='utf-8'?>\n")
            xml.write("<WinSSHTerm Version='1'>\n")
            for n in self.root.children:
                self.writeNode(n, xml)
            xml.write('</WinSSHTerm>')
            print "Created file '%s'" % conFile

    def __init__(self):
        wx.Frame.__init__(self, None, wx.ID_ANY, "Migrate2WinSSHTerm" + " " + __version__, size=(280,275), style=wx.DEFAULT_FRAME_STYLE & ~(wx.RESIZE_BORDER | wx.MAXIMIZE_BOX))
        panel = wx.Panel(self, -1)
        self.button1 = wx.Button(panel, id=-1, label='PuTTY / PuTTY Session Manager', pos=(10, 10), size=(245, 25))
        self.button1.Bind(wx.EVT_BUTTON, self.button1Click)
        self.button2 = wx.Button(panel, id=-1, label='MobaXterm', pos=(10, 10+25), size=(245, 25))
        self.button2.Bind(wx.EVT_BUTTON, self.button2Click)
        self.button3 = wx.Button(panel, id=-1, label='SuperPuTTY', pos=(10, 10+2*25), size=(245, 25))
        self.button3.Bind(wx.EVT_BUTTON, self.button3Click)
        self.button4 = wx.Button(panel, id=-1, label='mRemoteNG', pos=(10, 10+3*25), size=(245, 25))
        self.button4.Bind(wx.EVT_BUTTON, self.button4Click)
        self.button5 = wx.Button(panel, id=-1, label='MTPuTTY', pos=(10, 10+4*25), size=(245, 25))
        self.button5.Bind(wx.EVT_BUTTON, self.button5Click)
        self.button6 = wx.Button(panel, id=-1, label='PuTTY Connection Manager', pos=(10, 10+5*25), size=(245, 25))
        self.button6.Bind(wx.EVT_BUTTON, self.button6Click)
        self.button7 = wx.Button(panel, id=-1, label='KiTTY Classic', pos=(10, 10+6*25), size=(245, 25))
        self.button7.Bind(wx.EVT_BUTTON, self.button7Click)
        self.button8 = wx.Button(panel, id=-1, label='KiTTY Portable', pos=(10, 10+7*25), size=(245, 25))
        self.button8.Bind(wx.EVT_BUTTON, self.button8Click)
        self.button9 = wx.Button(panel, id=-1, label='Xshell', pos=(10, 10+8*25), size=(245, 25))
        self.button9.Bind(wx.EVT_BUTTON, self.button9Click)
        self.root = None

    def button1Click(self,event):
        self.root = Node('root')
        self.read_putty_registry()
        self.create_xml()

    def button2Click(self,event):
        self.root = Node('root')
        if self.read_mobaxterm_ini():
            self.create_xml()

    def button3Click(self,event):
        self.root = Node('root')
        if self.read_superputty_xml():
            self.create_xml()

    def button4Click(self,event):
        self.root = Node('root')
        if self.read_mremoteng_xml():
            self.create_xml()
            
    def button5Click(self,event):
        self.root = Node('root')
        if self.read_mtputty_xml():
            self.create_xml()

    def button6Click(self,event):
        self.root = Node('root')
        if self.read_puttycm_xml():
            self.create_xml()
    
    def button7Click(self,event):
        self.root = Node('root')
        self.read_kitty_registry()
        self.create_xml()
            
    def button8Click(self,event):
        self.root = Node('root')
        if self.read_kitty_filesystem():
            self.create_xml()

    def button9Click(self,event):
        self.root = Node('root')
        if self.read_xshell_filesystem():
            self.create_xml()

    def read_mtputty_xml(self):
        style = wx.FD_OPEN | wx.FD_FILE_MUST_EXIST
        dialog = wx.FileDialog(self, message='Open exported MTPuTTY tree (.xml)', wildcard='(*.xml)|*.xml', style=style)
        if dialog.ShowModal() == wx.ID_OK:
            file = dialog.GetPath()
        else:
            return False
        dialog.Destroy()
        try:
            tree = ET.parse(file)
            rt = tree.getroot()
            if rt.tag == "Servers":
                for c1 in rt:
                    if c1.tag == "Putty":
                        for child in c1:
                            if child.tag == "Node":                                 
                                self.mtputty_helper(child, self.root)
            elif rt.tag == "MTPutty":
                for c2 in rt:
                    if c2.tag == "Servers":
                        for cc2 in c2:
                            if cc2.tag == "Putty":
                                for child2 in cc2:
                                    if child2.tag == "Node":
                                        self.mtputty_helper(child2, self.root)
            return True
        except Exception as e:
            wx.MessageBox(str(e), "Error")
            return False            

    def mtputty_helper(self, node=None, parentNode=None):
        if node.attrib.get('Type') == '1':           
            name=""
            username=""
            hostname=""
            port=""
            for child in node:
                if not child.text is None:
                    if child.tag == "DisplayName":
                        name=str(child.text.encode('utf-8', 'ignore'))
                    if child.tag == "UserName":
                        username=str(child.text.encode('utf-8', 'ignore'))
                    if child.tag == "ServerName":
                        hostname=str(child.text.encode('utf-8', 'ignore'))
                    if child.tag == "Port":
                        port=str(child.text.encode('utf-8', 'ignore'))
                        if port == '0':
                            port='22'
            self.saveSessionData(
                    node=parentNode,
                    name=name,
                    username=username,
                    privateKey='',
                    hostname=hostname,
                    port=port
                    )    
        elif node.attrib.get('Type') == '0':
            for child in node:
                if child.tag == "DisplayName":
                    pathB64 = base64.b64encode(child.text.encode('utf-8', 'ignore'))
                    tmp = Node(pathB64, parent=parentNode, type="Container")                    
                else:
                    self.mtputty_helper(child, tmp)
            
    def read_mremoteng_xml(self):
        style = wx.FD_OPEN | wx.FD_FILE_MUST_EXIST
        dialog = wx.FileDialog(self, message='Open confCons.xml', wildcard='(*.XML)|*.XML', style=style)
        if dialog.ShowModal() == wx.ID_OK:
            file = dialog.GetPath()
        else:
            return False
        dialog.Destroy()
        try:
            tree = ET.parse(file)
            rt = tree.getroot()
            for child in rt:
                if child.tag == "Node":
                    self.mremoteng_helper(child, self.root)
            return True
        except Exception as e:
            wx.MessageBox(str(e), "Error")
            return False
            
    def mremoteng_helper(self, node=None, parentNode=None):
        if node.attrib.get('Type') == 'Connection':
            if node.attrib.get('Protocol') == "SSH2":
                self.saveSessionData(
                    node=parentNode,
                    name=str(node.attrib.get('Name').encode('utf-8', 'ignore')),
                    username=str(node.attrib.get('Username').encode('utf-8', 'ignore')),
                    privateKey='',
                    hostname=str(node.attrib.get('Hostname').encode('utf-8', 'ignore')),
                    port=str(node.attrib.get('Port').encode('utf-8', 'ignore'))
                    )
        elif node.attrib.get('Type') == 'Container':          
            pathB64 = base64.b64encode(node.attrib.get('Name').encode('utf-8', 'ignore'))
            tmp = Node(pathB64, parent=parentNode, type="Container")
            for child in node:
                self.mremoteng_helper(child, tmp)

    def read_puttycm_xml(self):
        style = wx.FD_OPEN | wx.FD_FILE_MUST_EXIST
        dialog = wx.FileDialog(self, message='Open exported connections xml', wildcard='(*.XML)|*.XML', style=style)
        if dialog.ShowModal() == wx.ID_OK:
            file = dialog.GetPath()
        else:
            return False
        dialog.Destroy()
        try:
            tree = ET.parse(file)
            rt = tree.getroot()
            if rt.tag == "configuration":
                for c1 in rt:
                    if c1.tag == "root":
                        for child in c1:
                            if child.tag == "container" or child.tag == "connection":
                                self.puttycm_helper(child, self.root)
            return True
        except Exception as e:
            wx.MessageBox(str(e), "Error")
            return False
            
    def puttycm_helper(self, node=None, parentNode=None):
        if node.tag == 'connection' and node.attrib.get('type') == 'PuTTY':
            name=""
            hostname=""
            port=""
            username=""
            for child1 in node:
                if child1.tag == 'connection_info':
                    for child2 in child1:
                        if not child2.text is None:
                            if child2.tag == "name":
                                name=str(child2.text.encode('utf-8', 'ignore'))
                            if child2.tag == "host":
                                hostname=str(child2.text.encode('utf-8', 'ignore'))
                            if child2.tag == "port":
                                port=str(child2.text.encode('utf-8', 'ignore'))
                elif child1.tag == 'login':
                    for child3 in child1:
                        if not child3.text is None:
                            if child3.tag == "login":
                                username=str(child3.text.encode('utf-8', 'ignore'))
            self.saveSessionData(
                    node=parentNode,
                    name=name,
                    username=username,
                    privateKey='',
                    hostname=hostname,
                    port=port
                    )    
        elif node.tag == 'container' and node.attrib.get('type') == 'folder':          
            pathB64 = base64.b64encode(node.attrib.get('name').encode('utf-8', 'ignore'))
            tmp = Node(pathB64, parent=parentNode, type="Container")
            for child in node:
                self.puttycm_helper(child, tmp)
      
    def read_superputty_xml(self):
        style = wx.FD_OPEN | wx.FD_FILE_MUST_EXIST
        dialog = wx.FileDialog(self, message='Open Sessions.XML', wildcard='(*.XML)|*.XML', style=style)
        if dialog.ShowModal() == wx.ID_OK:
            file = dialog.GetPath()
        else:
            return False
        dialog.Destroy()
        try:
            tree = ET.parse(file)
            for item in tree.iter():
                if item.tag == "SessionData":
                    sessionPath = item.attrib.get('SessionId')
                    list = sessionPath.encode('utf-8', 'ignore').split('/')
                    tmp = self.root
                    res = Resolver('name')
                    counter = 1
                    for i in list:
                        pathB64 = base64.b64encode(i)
                        try:
                            if res.get(tmp, pathB64):
                                tmp = res.get(tmp, pathB64)
                                if counter >= len(list):
                                    print pathB64
                                    self.saveSessionData(
                                        node=tmp,
                                        name=str(item.attrib.get('SessionName').encode('utf-8', 'ignore')),
                                        username=str(item.attrib.get('Username').encode('utf-8', 'ignore')),
                                        privateKey='',
                                        hostname=str(item.attrib.get('Host').encode('utf-8', 'ignore')),
                                        port=str(item.attrib.get('Port').encode('utf-8', 'ignore'))
                                        )
                                    print pathB64
                        except ChildResolverError as e:
                            if counter < len(list):
                                tmp = Node(pathB64, parent=tmp, type="Container")
                            if counter >= len(list):
                                self.saveSessionData(
                                    node=tmp,
                                    name=str(item.attrib.get('SessionName').encode('utf-8', 'ignore')),
                                    username=str(item.attrib.get('Username').encode('utf-8', 'ignore')),
                                    privateKey='',
                                    hostname=str(item.attrib.get('Host').encode('utf-8', 'ignore')),
                                    port=str(item.attrib.get('Port').encode('utf-8', 'ignore'))
                                    )
                        counter = counter + 1
            return True
        except Exception as e:
            wx.MessageBox(str(e), "Error")
            return False
            
    def read_mobaxterm_ini(self):
        style = wx.FD_OPEN | wx.FD_FILE_MUST_EXIST
        dialog = wx.FileDialog(self, message='Open MobaXterm.ini', wildcard='(*.ini)|*.ini', style=style)
        if dialog.ShowModal() == wx.ID_OK:
            file = dialog.GetPath()
        else:
            return False
        dialog.Destroy()
        try:
            config = configparser.RawConfigParser()
            config.optionxform = str
            config.read(file)
            res = Resolver('name')
            for s in config.sections():
                if s.startswith('Bookmarks'):
                    if config[s]['SubRep'] == 'PuTTY sessions':
                        continue
                    tmp = self.root
                    for (key,val) in config.items(s):
                        if key == 'ImgNum':
                            continue
                        if key == 'SubRep' and val:
                            sessionPath = config[s]['SubRep']
                            list = sessionPath.encode('utf-8', 'ignore').split('\\')
                            counter = 1
                            for i in list:
                                pathB64 = base64.b64encode(i)
                                try:
                                    if res.get(tmp, pathB64):
                                        tmp = res.get(tmp, pathB64)
                                except ChildResolverError as e:
                                    node = Node(pathB64, parent=tmp, type='Container')
                                    tmp = node
                                counter = counter + 1
                            break
                    for (key,val) in config.items(s):
                        if key == 'ImgNum' or key == 'SubRep':
                            continue
                        sessionData = val.encode('utf-8', 'ignore').split('%')
                        if sessionData[0] == '#109#0':
                            self.saveSessionData(tmp, key, sessionData[3], '', sessionData[1], sessionData[2])
            return True
        except Exception as e:
            wx.MessageBox(str(e), "Error")
            return False
            
    def read_xshell_filesystem(self):
        style = wx.DD_DEFAULT_STYLE | wx.DD_DIR_MUST_EXIST
        dialog = wx.DirDialog(self, message='Choose Xshell folder "Sessions"', style=style)
        if dialog.ShowModal() == wx.ID_OK:
            file = dialog.GetPath()
        else:
            return False
        dialog.Destroy()
        try:
            self.xshell_filesystem_helper(file, self.root)
            return True            
        except Exception as e:
            wx.MessageBox(str(e), "Error")
            return False

    def xshell_filesystem_helper(self, node=None, parentNode=None):
        list = os.listdir(node)
        for item in list:
            filename =  node + "\\" + item 
            if os.path.isfile(filename):
                if not filename.endswith(".xsh"):
                    continue
                hostname=""
                port=""
                username=""
                data=""
                with codecs.open(filename, 'r', 'utf-16') as f:
                    data = f.read()
                buf = StringIO.StringIO(data)
                config = configparser.RawConfigParser()
                config.optionxform = str
                config.readfp(buf)
                for s in config.sections():
                    if s == 'CONNECTION':
                        for (key,val) in config.items(s):
                            if key == "Port":
                                port=str(val)
                            if key == "Host":
                                hostname=str(val)
                    if s == 'CONNECTION:AUTHENTICATION':
                        for (key,val) in config.items(s):
                            if key == "UserName":
                                username=str(val)
                self.saveSessionData(
                    node=parentNode,
                    name=str(os.path.splitext(item)[0]),
                    username=username.encode('utf-8', 'ignore'),
                    privateKey='',
                    hostname=hostname.encode('utf-8', 'ignore'),
                    port=port.encode('utf-8', 'ignore')                   
                    )
            elif os.path.isdir(node + "\\" + item):          
                pathB64 = base64.b64encode(str(item))
                tmp = Node(pathB64, parent=parentNode, type="Container")
                self.xshell_filesystem_helper(node + "\\" + item , tmp)
            
    def read_putty_registry(self):
        aReg = ConnectRegistry(None, HKEY_CURRENT_USER)
        aKey = OpenKey(aReg, r"Software\SimonTatham\PuTTY\Sessions")
        res = Resolver('name')
        for i in range(0, QueryInfoKey(aKey)[0]):
            try:
                asubkey_name = EnumKey(aKey, i)
                if str(asubkey_name) == 'WinSSHTerm':
                    continue
                asubkey = OpenKey(aKey, asubkey_name)
                try:
                    sessionPath = str(QueryValueEx(asubkey, "PsmPath")[0].encode('utf-8', 'ignore'))
                except Exception as e:
                    sessionPath = "Sessions"
                    pass
                list = sessionPath.split('\\')
                tmp = self.root
                counter = 1
                for i in list:
                    pathB64 = base64.b64encode(i)
                    try:
                        if res.get(tmp, pathB64):
                            tmp = res.get(tmp, pathB64)
                            if counter >= len(list):
                                self.saveSessionData(
                                    node=tmp,
                                    name=str(asubkey_name),
                                    username=str(QueryValueEx(asubkey, "UserName")[0]),
                                    privateKey=str(QueryValueEx(asubkey, "PublicKeyFile")[0]),
                                    hostname=str(QueryValueEx(asubkey, "HostName")[0]),
                                    port=str(QueryValueEx(asubkey, "PortNumber")[0])
                                    )
                    except ChildResolverError as e:
                        tmp = Node(pathB64, parent=tmp, type="Container")
                        if counter >= len(list):
                            self.saveSessionData(
                                node=tmp,
                                name=str(asubkey_name),
                                username=str(QueryValueEx(asubkey, "UserName")[0]),
                                privateKey=str(QueryValueEx(asubkey, "PublicKeyFile")[0]),
                                hostname=str(QueryValueEx(asubkey, "HostName")[0]),
                                port=str(QueryValueEx(asubkey, "PortNumber")[0])
                                )
                    counter = counter + 1
            except EnvironmentError as e:
                break

    def read_kitty_registry(self):
        aReg = ConnectRegistry(None, HKEY_CURRENT_USER)
        aKey = OpenKey(aReg, r"Software\9bis.com\KiTTY\Sessions")
        res = Resolver('name')
        for i in range(0, QueryInfoKey(aKey)[0]):
            try:
                asubkey_name = EnumKey(aKey, i)
                if str(asubkey_name) == 'WinSSHTerm':
                    continue
                asubkey = OpenKey(aKey, asubkey_name)
                try:
                    sessionPath = str(QueryValueEx(asubkey, "PsmPath")[0].encode('utf-8', 'ignore'))
                except Exception as e:
                    sessionPath = "Sessions"
                    pass
                list = sessionPath.split('\\')
                tmp = self.root
                counter = 1
                for i in list:
                    pathB64 = base64.b64encode(i)
                    try:
                        if res.get(tmp, pathB64):
                            tmp = res.get(tmp, pathB64)
                            if counter >= len(list):
                                self.saveSessionData(
                                    node=tmp,
                                    name=str(asubkey_name),
                                    username=str(QueryValueEx(asubkey, "UserName")[0]),
                                    privateKey=str(QueryValueEx(asubkey, "PublicKeyFile")[0]),
                                    hostname=str(QueryValueEx(asubkey, "HostName")[0]),
                                    port=str(QueryValueEx(asubkey, "PortNumber")[0])
                                    )
                    except ChildResolverError as e:
                        tmp = Node(pathB64, parent=tmp, type="Container")
                        if counter >= len(list):
                            self.saveSessionData(
                                node=tmp,
                                name=str(asubkey_name),
                                username=str(QueryValueEx(asubkey, "UserName")[0]),
                                privateKey=str(QueryValueEx(asubkey, "PublicKeyFile")[0]),
                                hostname=str(QueryValueEx(asubkey, "HostName")[0]),
                                port=str(QueryValueEx(asubkey, "PortNumber")[0])
                                )
                    counter = counter + 1
            except EnvironmentError as e:
                break

    def read_kitty_filesystem(self):
        style = wx.DD_DEFAULT_STYLE | wx.DD_DIR_MUST_EXIST
        dialog = wx.DirDialog(self, message='Choose KiTTY folder "Sessions"', style=style)
        if dialog.ShowModal() == wx.ID_OK:
            file = dialog.GetPath()
        else:
            return False
        dialog.Destroy()
        try:
            self.kitty_filesystem_helper(file, self.root)
            return True            
        except Exception as e:
            wx.MessageBox(str(e), "Error")
            return False

    def kitty_filesystem_helper(self, node=None, parentNode=None):
        list = os.listdir(node)
        for item in list:
            if os.path.isfile(node + "\\" + item):
                hostname=""
                port=""
                username=""
                with open(node + "\\" + item, 'r') as f:
                    lines = f.readlines()
                for line in lines:
                    if line.startswith('HostName\\'):
                        hostname = str(line.strip().split('\\')[1])
                    if line.startswith('PortNumber\\'):
                        port = str(line.strip().split('\\')[1])
                    if line.startswith('UserName\\'):
                        username = str(line.strip().split('\\')[1])
                self.saveSessionData(
                    node=parentNode,
                    name=str(urllib.unquote(item.decode('utf-8', 'ignore'))),
                    username=username.encode('utf-8', 'ignore'),
                    privateKey='',
                    hostname=hostname.encode('utf-8', 'ignore'),
                    port=port.encode('utf-8', 'ignore')                   
                    )
            elif os.path.isdir(node + "\\" + item):          
                pathB64 = base64.b64encode(str(item))
                tmp = Node(pathB64, parent=parentNode, type="Container")
                self.kitty_filesystem_helper(node + "\\" + item , tmp)
                    
if __name__ == "__main__":
    reload(sys)
    sys.setdefaultencoding("ISO-8859-1")
    codecs.register_error("strict", codecs.ignore_errors)
    app = wx.App(False)
    frame = Migrate2WinSSHTerm()
    frame.Show()
    app.MainLoop()
