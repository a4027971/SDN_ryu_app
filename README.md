開始
========
前置作業
--------
安裝Ryu控制器和mininet模擬器。

執行應用程式
--------
**1. 建立胖樹拓墣**

    $ sudo {file_path}/fatTreeTopology.py

**2. 執行控制器程式碼**

    $ ryu-manager --observe-links {file_path}/fatTreeMultipath.py

**3. 測試**

    minimet> h001 ping h005
    
    
[參考投影片](https://goo.gl/eHKtGc)

Getting started
========
Before
--------
Install Ryu controller and mininet.

Run the application
--------
**1. Generate Fattree topology**

    $ sudo {file_path}/fatTreeTopology.py

**2. Execute controller code**

    $ ryu-manager --observe-links {file_path}/fatTreeMultipath.py

**3. Test**

    minimet> h001 ping h005

[reference power point](https://goo.gl/eHKtGc)
