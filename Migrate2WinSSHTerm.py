__author__ = 'Alex D., P-St'
__version__ = '0.1'

import wx
from anytree import Node, Resolver, ChildResolverError
import base64
from _winreg import *
import configparser

class Migrate2WinSSHTerm(wx.Frame):
    def saveSessionData(self, node=None, name=None, username=None, privateKey=None, hostname=None, port=None):
        Node(name,
            parent=node,
            type="Connection",
            username=username,
            pubkey=privateKey,
            hostname=hostname,
            port=port
            )

    def writeNode(self, node=None, xml=None):
        if node.type == 'Container':
            xml.write("<Node Name='%s' Type='Container' Expanded='True'>\n" % base64.b64decode(node.name))
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
            xml = open(conFile, 'w')
            xml.write("<?xml version='1.0' encoding='utf-8'?>\n")
            xml.write("<WinSSHTerm Version='1'>\n")
            for n in self.root.children:
                self.writeNode(n, xml)
            xml.write('</WinSSHTerm>')
            #print "Created file '%s'" % conFile

    def __init__(self):
        wx.Frame.__init__(self, None, wx.ID_ANY, "Migrate2WinSSHTerm", size=(280,200))
        panel = wx.Panel(self, -1)
        self.button1 = wx.Button(panel, id=-1, label='PuTTY / PuTTY Session Manager', pos=(10, 10), size=(245, 25))
        self.button1.Bind(wx.EVT_BUTTON, self.button1Click)
        self.button2 = wx.Button(panel, id=-1, label='MobaXterm', pos=(10, 10+25), size=(245, 25))
        self.button2.Bind(wx.EVT_BUTTON, self.button2Click)
        self.root = None

    def button1Click(self,event):
        self.root = Node('root')
        self.read_putty_registry()
        self.create_xml()

    def button2Click(self,event):
        self.root = Node('root')
        self.read_mobaxterm_ini()
        self.create_xml()

    def read_mobaxterm_ini(self):
        style = wx.FD_OPEN | wx.FD_FILE_MUST_EXIST
        dialog = wx.FileDialog(self, message='Open MobaXterm.ini', wildcard='(*.ini)|*.ini', style=style)
        if dialog.ShowModal() == wx.ID_OK:
            file = dialog.GetPath()
        else:
            file = None
        dialog.Destroy()
        if file != None:
            config = configparser.RawConfigParser()
            config.optionxform = str
            config.read('MobaXterm.ini')
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
                            list = sessionPath.encode('utf-8').split('\\')
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
                        sessionData = val.encode('utf-8').split('%')
                        if sessionData[0] == '#109#0':
                            self.saveSessionData(tmp, key, sessionData[3], '', sessionData[1], sessionData[2])

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
                    sessionPath = str(QueryValueEx(asubkey, "PsmPath")[0].encode('utf-8'))
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

if __name__ == "__main__":
    app = wx.App(False)
    frame = Migrate2WinSSHTerm()
    frame.Show()
    app.MainLoop()