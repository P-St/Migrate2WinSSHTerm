__author__ = 'Alex D., P-St'
__version__ = '0.22'

import wx
from anytree import Node, Resolver, ChildResolverError
import base64
from winreg import *
import configparser
from xml.sax.saxutils import escape
import xml.etree.ElementTree as ET
import os
from urllib.parse import unquote
import codecs
import sys
from io import StringIO
from collections import defaultdict

class Migrate2WinSSHTerm(wx.Frame):
    def saveSessionData(self,
        node=None,
        name=None,
        username=None,
        privateKey=None,
        hostname=None,
        port=None,
        certificate=None,
        launchTool=None,
        x11Forward=None,
        copyFilesProtocol=None,
        proxyType=None,
        proxyHost=None,
        proxyPort=None,
        proxyUsername=None,
        proxyTelnetCommand=None      
    ):
        Node(
        escape(name, {'"': '&quot;'}) if name is not None else None,
        parent=node,
        type="Connection",
        username=escape(username, {'"': '&quot;'}) if username is not None else '',
        pubkey=escape(privateKey, {'"': '&quot;'}) if privateKey is not None else '',
        hostname=escape(hostname, {'"': '&quot;'}) if hostname is not None else '',
        port=escape(port, {'"': '&quot;'}) if port is not None else '',
        certificate=escape(certificate, {'"': '&quot;'}) if certificate is not None else '',
        launchTool=escape(launchTool, {'"': '&quot;'}) if launchTool is not None else '',
        x11Forward=escape(x11Forward, {'"': '&quot;'}) if x11Forward is not None else '',
        copyFilesProtocol=escape(copyFilesProtocol, {'"': '&quot;'}) if copyFilesProtocol is not None else '',
        proxy="enabled" if proxyType is not None else "disabled",
        proxyType=escape(proxyType, {'"': '&quot;'}) if proxyType is not None else '',
        proxyHost=escape(proxyHost, {'"': '&quot;'}) if proxyHost is not None else '',
        proxyPort=escape(proxyPort, {'"': '&quot;'}) if proxyPort is not None else '',
        proxyUsername=escape(proxyUsername, {'"': '&quot;'}) if proxyUsername is not None else '',
        proxyTelnetCommand=escape(proxyTelnetCommand, {'"': '&quot;'}) if proxyTelnetCommand is not None else ''
        )

    def writeNode(self, node=None, xml=None):
        if node.type == 'Container':
            xml.write("<Node Name='%s' Type='Container' Expanded='True'>\n" % escape(base64.b64decode(node.name).decode('UTF-8') ))
            for n in node.children:
                self.writeNode(n, xml)
            xml.write('</Node>\n')
        if node.type == 'Connection':
            node_data = (
                f'<Node'
                f' Name="{node.name}"'
                f' Type="Connection"'
                f' Descr=""'
                f' Username="{node.username}"'
                f' Password=""'
                f' PrivateKey="{node.pubkey}"'
                f' Hostname="{node.hostname}"'
                f' Port="{node.port}"'
                f' Certificate="{node.certificate}"'
                f' LaunchToolInt="{node.launchTool}"'
                f' sX11="{node.x11Forward}"'
                f' cfProt="{node.copyFilesProtocol}"'
                f' pSshProxy="{node.proxy}"'
                f' pType="{node.proxyType}"'
                f' pHost="{node.proxyHost}"'
                f' pPort="{node.proxyPort}"'
                f' pUser="{node.proxyUsername}"'
                f' pTelnetCmd="{node.proxyTelnetCommand}"'
                f' />\n'
            )
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
            print("Created file '%s'" % conFile)

    def __init__(self):
        wx.Frame.__init__(self, None, wx.ID_ANY, "Migrate2WinSSHTerm" + " " + __version__, size=(280,325), style=wx.DEFAULT_FRAME_STYLE & ~(wx.RESIZE_BORDER | wx.MAXIMIZE_BOX))
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
        self.button10 = wx.Button(panel, id=-1, label='SecureCRT', pos=(10, 10+9*25), size=(245, 25))
        self.button10.Bind(wx.EVT_BUTTON, self.button10Click)
        self.button11 = wx.Button(panel, id=-1, label='RoyalTS', pos=(10, 10+10*25), size=(245, 25))
        self.button11.Bind(wx.EVT_BUTTON, self.button11Click)
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
    
    def button10Click(self,event):
        self.root = Node('root')
        if self.read_securecrt_xml():
            self.create_xml()

    def button11Click(self, event):
        self.root = Node('root')
        if self.read_royalts_xml():
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
                        name=str(child.text)
                    if child.tag == "UserName":
                        username=str(child.text)
                    if child.tag == "ServerName":
                        hostname=str(child.text)
                    if child.tag == "Port":
                        port=str(child.text)
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
                    pathB64 = base64.b64encode(child.text.encode())
                    tmp = Node(pathB64, parent=parentNode, type="Container")                    
                else:
                    self.mtputty_helper(child, tmp)

    def read_securecrt_xml(self):
        style = wx.FD_OPEN | wx.FD_FILE_MUST_EXIST
        dialog = wx.FileDialog(self, message='Open exported XML (Tools->Export Settings)', wildcard='(*.XML)|*.XML', style=style)
        if dialog.ShowModal() == wx.ID_OK:
            file = dialog.GetPath()
        else:
            return False
        dialog.Destroy()
        try:
            tree = ET.parse(file)
            rt = tree.getroot()
            for child in rt:
                if child.tag == "key" and child.attrib.get('name') == 'Sessions':
                    for session_child in child:
                        self.securecrt_helper(session_child, self.root)
            return True
        except Exception as e:
            wx.MessageBox(str(e), "Error")
            return False
            
    def securecrt_helper(self, node=None, parentNode=None):
        name=""
        username=""
        hostname=""
        port=""
        isContainer=True
        for child in node:
            if child.tag == "dword" or child.tag == "string":
                isContainer=False
                break              
        if isContainer:
            pathB64 = base64.b64encode(node.attrib.get('name').encode())
            tmp = Node(pathB64, parent=parentNode, type="Container")
            for child in node:
                self.securecrt_helper(child, tmp)
        else:
            for child in node:
                name=str(node.attrib.get('name'))
                if child.tag == "string" and child.attrib.get('name') == 'Hostname':
                    hostname=str(child.text)
                if child.tag == "string" and child.attrib.get('name') == 'Username':
                    username=str(child.text)
                if child.tag == "dword" and child.attrib.get('name') == '[SSH2] Port':
                    port=str(child.text)
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
                    name=str(node.attrib.get('Name')),
                    username=str(node.attrib.get('Username')),
                    hostname=str(node.attrib.get('Hostname')),
                    port=str(node.attrib.get('Port'))
                    )
            elif node.attrib.get('Protocol') == "RDP":
                self.saveSessionData(
                    node=parentNode,
                    name=str(node.attrib.get('Name')),
                    username=str(node.attrib.get('Username')),
                    launchTool='RDP client',
                    hostname=str(node.attrib.get('Hostname')),
                    port=str(node.attrib.get('Port'))
                    )
            elif node.attrib.get('Protocol') == "VNC":
                self.saveSessionData(
                    node=parentNode,
                    name=str(node.attrib.get('Name')),
                    username=str(node.attrib.get('Username')),
                    launchTool='VNC client',
                    hostname=str(node.attrib.get('Hostname')),
                    port=str(node.attrib.get('Port'))
                    )

        elif node.attrib.get('Type') == 'Container':          
            pathB64 = base64.b64encode(node.attrib.get('Name').encode())
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
                                name=str(child2.text)
                            if child2.tag == "host":
                                hostname=str(child2.text)
                            if child2.tag == "port":
                                port=str(child2.text)
                elif child1.tag == 'login':
                    for child3 in child1:
                        if not child3.text is None:
                            if child3.tag == "login":
                                username=str(child3.text)
            self.saveSessionData(
                    node=parentNode,
                    name=name,
                    username=username,
                    privateKey='',
                    hostname=hostname,
                    port=port
                    )    
        elif node.tag == 'container' and node.attrib.get('type') == 'folder':          
            pathB64 = base64.b64encode(node.attrib.get('name').encode())
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
                    list = sessionPath.split('/')
                    tmp = self.root
                    res = Resolver('name')
                    counter = 1
                    for i in list:
                        pathB64 = base64.b64encode(i.encode())
                        try:
                            if res.get(tmp, pathB64.decode()):
                                tmp = res.get(tmp, pathB64.decode())
                                if counter >= len(list):
                                    self.saveSessionData(
                                        node=tmp,
                                        name=str(item.attrib.get('SessionName')),
                                        username=str(item.attrib.get('Username')),
                                        privateKey='',
                                        hostname=str(item.attrib.get('Host')),
                                        port=str(item.attrib.get('Port'))
                                        )
                        except ChildResolverError as e:
                            if counter < len(list):
                                tmp = Node(pathB64, parent=tmp, type="Container")
                            if counter >= len(list):
                                self.saveSessionData(
                                    node=tmp,
                                    name=str(item.attrib.get('SessionName')),
                                    username=str(item.attrib.get('Username')),
                                    privateKey='',
                                    hostname=str(item.attrib.get('Host')),
                                    port=str(item.attrib.get('Port'))
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
            config = configparser.RawConfigParser(strict=False)
            config.optionxform = str
            config.read(file)
            res = Resolver('name')
            for s in config.sections():
                if s.startswith('Bookmarks'):                    
                    if config[s]['SubRep'] == 'PuTTY sessions':
                        continue
                    if config[s]['SubRep'] == 'SCRT sessions':
                        continue
                    if config[s]['SubRep'] == 'SuperPuTTY sessions':
                        continue
                    tmp = self.root
                    for (key,val) in config.items(s):
                        if key == 'ImgNum':
                            continue
                        if key == 'SubRep' and val:
                            sessionPath = config[s]['SubRep']
                            list = sessionPath.split('\\')
                            counter = 1
                            for i in list:
                                pathB64 = base64.b64encode(i.encode())
                                try:
                                    if res.get(tmp, pathB64.decode()):
                                        tmp = res.get(tmp, pathB64.decode())
                                except ChildResolverError as e:
                                    node = Node(pathB64, parent=tmp, type='Container')
                                    tmp = node
                                counter = counter + 1
                            break
                    for (key,val) in config.items(s):
                        if key == 'ImgNum' or key == 'SubRep':
                            continue
                        try:
                            sessionData = val.split('%')
                            saveSession = False
                            lt = ''
                            prot = sessionData[0][sessionData[0].rfind('#') + 1:]
                            if prot == '0':
                                saveSession = True
                            elif prot == '4':
                                lt = 'RDP client'
                                saveSession = True
                            elif prot == '5':
                                lt = 'VNC client'
                                saveSession = True
                            if saveSession:
                                self.saveSessionData(node=tmp, 
                                                name=key,
                                                username=sessionData[3],
                                                privateKey=sessionData[14],
                                                hostname=sessionData[1],
                                                port=sessionData[2],
                                                launchTool=lt)  
                        except Exception as e:
                            continue            
            return True
        except Exception as e:
            wx.MessageBox(str(e), "Error")
            return False
            
    def read_xshell_filesystem(self):
        style = wx.DD_DEFAULT_STYLE | wx.DD_DIR_MUST_EXIST
        dialog = wx.DirDialog(self, message='Choose Xshell folder "Sessions" (should be inside your "My documents" folder)', style=style)
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
                buf = StringIO(data)
                config = configparser.RawConfigParser()
                config.optionxform = str
                config.read_file(buf)
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
                    username=username,
                    privateKey='',
                    hostname=hostname,
                    port=port                   
                    )
            elif os.path.isdir(node + "\\" + item):          
                pathB64 = base64.b64encode(str(item).encode())
                tmp = Node(pathB64, parent=parentNode, type="Container")
                self.xshell_filesystem_helper(node + "\\" + item , tmp)
            
    def read_putty_registry(self):
        aReg = ConnectRegistry(None, HKEY_CURRENT_USER)
        aKey = OpenKey(aReg, r"Software\SimonTatham\PuTTY\Sessions")
        pathB64 = base64.b64encode("Sessions".encode())
        sessions_container = Node(pathB64, parent=self.root, type="Container")      
        for i in range(0, QueryInfoKey(aKey)[0]):
            try:
                asubkey_name = EnumKey(aKey, i)
                if str(asubkey_name) == 'WinSSHTerm' or str(asubkey_name) == 'WinSSHTerm_ScriptRunner':
                    continue
                asubkey = OpenKey(aKey, asubkey_name)
                lclProxyMethod=str(QueryValueEx(asubkey, "ProxyMethod")[0])
                if lclProxyMethod == "1":
                    tmpProxyType = 'SOCKS4'
                elif lclProxyMethod == "2":
                    tmpProxyType = 'SOCKS5'
                elif lclProxyMethod == "3":
                    tmpProxyType = 'HTTP'
                elif lclProxyMethod == "5":
                    tmpProxyType = 'Local'
                else:
                    tmpProxyType=None
                if "tsh.exe" in str(QueryValueEx(asubkey, "ProxyTelnetCommand")[0]):
                    self.saveSessionData(
                        node=sessions_container,
                        name=self.unescape_registry_key(str(asubkey_name)),
                                    username=str(QueryValueEx(asubkey, "UserName")[0]),
                                    privateKey=str(QueryValueEx(asubkey, "PublicKeyFile")[0]),
                                    hostname=str(QueryValueEx(asubkey, "HostName")[0]),
                                    port=str(QueryValueEx(asubkey, "PortNumber")[0]),
                                    certificate=str(QueryValueEx(asubkey, "DetachedCertificate")[0]),
                                    x11Forward="don't forward",
                                    copyFilesProtocol="sftp",
                                    proxyType=tmpProxyType,
                                    proxyHost=str(QueryValueEx(asubkey, "ProxyHost")[0]),
                                    proxyPort=str(QueryValueEx(asubkey, "ProxyPort")[0]),
                                    proxyUsername=str(QueryValueEx(asubkey, "ProxyUsername")[0]),
                                    proxyTelnetCommand=str(QueryValueEx(asubkey, "ProxyTelnetCommand")[0])
                    )
                else:
                    self.saveSessionData(
                        node=sessions_container,
                        name=self.unescape_registry_key(str(asubkey_name)),
                                    username=str(QueryValueEx(asubkey, "UserName")[0]),
                                    privateKey=str(QueryValueEx(asubkey, "PublicKeyFile")[0]),
                                    hostname=str(QueryValueEx(asubkey, "HostName")[0]),
                                    port=str(QueryValueEx(asubkey, "PortNumber")[0]),
                                    certificate=str(QueryValueEx(asubkey, "DetachedCertificate")[0]),
                                    proxyType=tmpProxyType,
                                    proxyHost=str(QueryValueEx(asubkey, "ProxyHost")[0]),
                                    proxyPort=str(QueryValueEx(asubkey, "ProxyPort")[0]),
                                    proxyUsername=str(QueryValueEx(asubkey, "ProxyUsername")[0]),
                                    proxyTelnetCommand=str(QueryValueEx(asubkey, "ProxyTelnetCommand")[0])
                    )
            except EnvironmentError:
                break
    def unescape_registry_key(self, input_str):
        output_str = []
        i = 0
        while i < len(input_str):
            if input_str[i] == '%' and i + 2 < len(input_str):
                hex_value = int(input_str[i+1:i+3], 16)
                output_str.append(chr(hex_value))
                i += 3
            else:
                output_str.append(input_str[i])
                i += 1
        return ''.join(output_str)

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
                    sessionPath = str(QueryValueEx(asubkey, "PsmPath")[0])
                except Exception as e:
                    sessionPath = "Sessions"
                    pass
                list = sessionPath.split('\\')
                tmp = self.root
                counter = 1
                for i in list:
                    pathB64 = base64.b64encode(i.encode())
                    try:
                        if res.get(tmp, pathB64.decode()):
                            tmp = res.get(tmp, pathB64.decode())
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
                    name=str(unquote(item)),
                    username=username,
                    privateKey='',
                    hostname=hostname,
                    port=port                   
                    )
            elif os.path.isdir(node + "\\" + item):          
                pathB64 = base64.b64encode(str(item).encode())
                tmp = Node(pathB64, parent=parentNode, type="Container")
                self.kitty_filesystem_helper(node + "\\" + item , tmp)

    def read_royalts_xml(self):
        style = wx.FD_OPEN | wx.FD_FILE_MUST_EXIST
        dialog = wx.FileDialog(self, message='Open RoyalTS document (.rtsz)', wildcard='(*.rtsz)|*.rtsz', style=style)
        if dialog.ShowModal() == wx.ID_OK:
            file = dialog.GetPath()
        else:
            return False
        dialog.Destroy()
        try:
            tree = ET.parse(file)
            root = tree.getroot()
            royal_doc = root.find("RoyalDocument")
            if royal_doc is None:
                raise ValueError("Invalid RoyalTS file - missing RoyalDocument element")
            root_id = royal_doc.find("ID").text
            id_to_node = {root_id: self.root}
            trash_ids = set()
            elements = []
            position_map = defaultdict(list)
            for elem in root:
                if elem.tag not in ["RoyalFolder", "RoyalSSHConnection", 
                                  "RoyalVNCConnection", "RoyalRDSConnection", 
                                  "RoyalTrash"]:
                    continue
                elem_id = elem.find("ID").text
                parent_id = elem.find("ParentID").text if elem.find("ParentID") is not None else root_id
                position = int(elem.find("PositionNr").text) if elem.find("PositionNr") is not None else 0
                if elem.tag == "RoyalTrash":
                    trash_ids.add(elem_id)
                    continue
                elements.append({
                    "elem": elem,
                    "id": elem_id,
                    "parent_id": parent_id,
                    "position": position,
                    "type": elem.tag
                })
                position_map[parent_id].append((position, elem_id))
            for parent in position_map:
                position_map[parent].sort(key=lambda x: x[0])
            processed = set()
            queue = [(root_id, self.root)]
            while queue:
                current_parent_id, current_parent_node = queue.pop(0)
                for pos, elem_id in position_map.get(current_parent_id, []):
                    element = next((e for e in elements if e["id"] == elem_id), None)
                    if not element or element["id"] in processed:
                        continue
                    processed.add(element["id"])
                    if element["type"] == "RoyalFolder":
                        name = element["elem"].find("Name").text
                        pathB64 = base64.b64encode(name.encode()).decode('utf-8')
                        folder_node = Node(pathB64, parent=current_parent_node, type="Container")
                        id_to_node[element["id"]] = folder_node
                        queue.append((element["id"], folder_node))
                    else:
                        conn = element["elem"]
                        name_elem = conn.find("Name")
                        name = name_elem.text if name_elem is not None else "Unnamed Connection"
                        host_elem = conn.find("URI")
                        host = host_elem.text if host_elem is not None else ""
                        port_elem = conn.find("Port") if conn.find("Port") is not None else conn.find("RDPPort")
                        port = port_elem.text if port_elem is not None else (
                            "22" if element["type"] == "RoyalSSHConnection" else
                            "3389" if element["type"] == "RoyalRDSConnection" else 
                            "5900"
                        )
                        launch_tool = {
                            "RoyalSSHConnection": "",
                            "RoyalRDSConnection": "RDP client",
                            "RoyalVNCConnection": "VNC client"
                        }[element["type"]]
                        self.saveSessionData(
                            node=current_parent_node,
                            name=name,
                            hostname=host,
                            port=port,
                            launchTool=launch_tool
                        )
            return True
        except Exception as e:
            wx.MessageBox(f"Error parsing RoyalTS file: {str(e)}", "Error")
            return False

if __name__ == "__main__":
    codecs.register_error("strict", codecs.ignore_errors)
    app = wx.App(False)
    frame = Migrate2WinSSHTerm()
    frame.Show()
    app.MainLoop()
