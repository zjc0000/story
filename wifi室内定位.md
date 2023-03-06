#### An_Encoded_LSTM_Network_Model_for_WiFi-based_Indoor_Positioning
RSS信息样本集过于稀疏，采用全连接层提取特征，LSTM来做决策，没有采用传统的WKNN算法。

![](https://raw.githubusercontent.com/zjc0000/story_images/main/小书匠/1678092838264.png)
#### **An_improved_WiFi_indoor_localization_method_combining_channel_state_information_and_received_signal_strength**
同时使用CSI信息和RSS信息作为样本集特征值
（1）CSI转化为CIR，可参照matlab示例相同做法openExample('wlan/PositioningWith80211azFingerprintingAndDeepLearningExample')
（2）根据相关带宽降维，从子载波数降维为子信道数

![](https://raw.githubusercontent.com/zjc0000/story_images/main/小书匠/1677571178828.png)
（3）WKNN算法中引入核方法kernel methods来筛选AP并计算WKNN的权重，同时考虑rss和csi，μ是可调节的参数来平衡rss和csi的在定位时所占比重
positoning问题，根据权重计算具体位置坐标

![](https://raw.githubusercontent.com/zjc0000/story_images/main/小书匠/1677828267742.png)

#### **WiFi_Indoor_Location_Method_Based_on_RSSI**
（1）引入loss rate减小样本集，只选择实测数据时出现次数大于某一阈值的AP。同时也考虑稳定性，只选择方差小于某一阈值的AP.

![](https://raw.githubusercontent.com/zjc0000/story_images/main/小书匠/1677571775123.png)
（2）WKNN算法中引入曼哈顿距离替代欧氏距离，用RSSI的曼哈顿距离来筛选AP并计算WKNN的权重
positoning问题，根据权重计算具体位置坐标

![](https://raw.githubusercontent.com/zjc0000/story_images/main/小书匠/1677571456705.png)

#### **Indoor_2.5D_Positioning_of_WiFi_Based_on_SVM**
选择最优AP流程图，考虑RSSI平均强度（maxmean），稳定性（方差）以及AP间干扰
 属于location问题，找到最近的AP

![](https://raw.githubusercontent.com/zjc0000/story_images/main/小书匠/1677571941989.png)