/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "medialibrary_device.h"
#include "medialibrary_device_test.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
class ConfigTestOpenCall : public NativeRdb::RdbOpenCallback {
public:
    int OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override;
    static const string CREATE_TABLE_TEST;
};

const string ConfigTestOpenCall::CREATE_TABLE_TEST = string("CREATE TABLE IF NOT EXISTS test ") +
    "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)";

int ConfigTestOpenCall::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int ConfigTestOpenCall::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return 0;
}

shared_ptr<NativeRdb::RdbStore> storePtr = nullptr;
void MediaLibraryDeviceTest::SetUpTestCase(void)
{
    const string dbPath = "/data/test/medialibrary_device_test.db";
    NativeRdb::RdbStoreConfig config(dbPath);
    ConfigTestOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    storePtr = store;
}

void MediaLibraryDeviceTest::TearDownTestCase(void)
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

// SetUp:Execute before each test case
void MediaLibraryDeviceTest::SetUp() {}

void MediaLibraryDeviceTest::TearDown(void) {}

HWTEST_F(MediaLibraryDeviceTest, medialib_InitDeviceRdbStore_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    shared_ptr<MediaLibraryDevice> deviceTest = MediaLibraryDevice::GetInstance();
    deviceTest->Start();
    bool ret = deviceTest->InitDeviceRdbStore(nullptr);
    EXPECT_EQ(ret, false);
    ret = deviceTest->InitDeviceRdbStore(storePtr);
    EXPECT_EQ(ret, true);
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    deviceTest->Stop();
    deviceInfo.networkId[0] = 'a';
    deviceTest->OnDeviceReady(deviceInfo);
    deviceTest->Start();
    deviceTest->OnDeviceReady(deviceInfo);
    deviceTest->Stop();
    deviceTest->OnDeviceOnline(deviceInfo);
    deviceTest->OnDeviceChanged(deviceInfo);
    deviceTest->OnRemoteDied();
    deviceTest->Start();
    deviceTest->NotifyDeviceChange();
    deviceTest->NotifyRemoteFileChange();
    deviceTest->Stop();
}

HWTEST_F(MediaLibraryDeviceTest, medialib_UpdateDeviceSyncStatus_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    shared_ptr<MediaLibraryDevice> deviceTest = MediaLibraryDevice::GetInstance();
    string networkIdTest = "UpdateDeviceSyncStatus";
    int32_t syncStatus = 1;
    deviceTest->Start();
    bool ret = deviceTest->UpdateDeviceSyncStatus(networkIdTest, MEDIALIBRARY_TABLE, syncStatus);
    EXPECT_EQ(ret, false);
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    deviceInfo.networkId[0] = 'a';
    deviceTest->DevOnlineProcess(deviceInfo);
    ret = deviceTest->UpdateDeviceSyncStatus(networkIdTest, MEDIALIBRARY_TABLE, syncStatus);
    EXPECT_EQ(ret, false);
    deviceTest->Stop();
}

HWTEST_F(MediaLibraryDeviceTest, medialib_GetNetworkIdBySelfId_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    shared_ptr<MediaLibraryDevice> deviceTest = MediaLibraryDevice::GetInstance();
    string selfId = "GetNetworkIdBySelfId";
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    deviceInfo.networkId[0] = 'a';
    deviceTest->Start();
    deviceTest->DevOnlineProcess(deviceInfo);
    string ret = deviceTest->GetNetworkIdBySelfId(selfId);
    EXPECT_EQ(ret, "");
    ret = deviceTest->GetNetworkIdBySelfId(selfId);
    EXPECT_EQ(ret, "");
    deviceTest->Stop();
}

HWTEST_F(MediaLibraryDeviceTest, medialib_GetUdidByNetworkId_test_001, TestSize.Level0)
{
    shared_ptr<MediaLibraryDevice> deviceTest = MediaLibraryDevice::GetInstance();
    string networkId = "";
    deviceTest->Start();
    string ret = deviceTest->GetUdidByNetworkId(networkId);
    EXPECT_NE(ret, "");
    networkId = "GetUdidByNetworkId";
    ret = deviceTest->GetUdidByNetworkId(networkId);
    EXPECT_EQ(ret, "");
    deviceTest->Stop();
}

HWTEST_F(MediaLibraryDeviceTest, medialib_GetDeviceInfoMap_test_001, TestSize.Level0)
{
    shared_ptr<MediaLibraryDevice> deviceTest = MediaLibraryDevice::GetInstance();
    EXPECT_NE(deviceTest, nullptr);
    deviceTest->Start();
    unordered_map<string, MediaLibraryDeviceInfo> outDeviceMap;
    deviceTest->GetDeviceInfoMap(outDeviceMap);
    deviceTest->Stop();
}

HWTEST_F(MediaLibraryDeviceTest, medialib_QueryAgingDeviceInfos_test_001, TestSize.Level0)
{
    shared_ptr<MediaLibraryDevice> deviceTest = MediaLibraryDevice::GetInstance();
    deviceTest->Start();
    vector<MediaLibraryDeviceInfo> outDeviceInfos;
    bool ret = deviceTest->QueryAgingDeviceInfos(outDeviceInfos);
    EXPECT_EQ(ret, false);
    deviceTest->Stop();
}

HWTEST_F(MediaLibraryDeviceTest, medialib_QueryAllDeviceUdid_test_001, TestSize.Level0)
{
    shared_ptr<MediaLibraryDevice> deviceTest = MediaLibraryDevice::GetInstance();
    deviceTest->Start();
    vector<string> deviceUdids;
    bool ret = deviceTest->QueryAllDeviceUdid(deviceUdids);
    EXPECT_EQ(ret, true);
    deviceTest->Stop();
}

HWTEST_F(MediaLibraryDeviceTest, medialib_DeleteDeviceInfo_test_001, TestSize.Level0)
{
    shared_ptr<MediaLibraryDevice> deviceTest = MediaLibraryDevice::GetInstance();
    EXPECT_NE(deviceTest, nullptr);
    deviceTest->Start();
    string udid = "";
    bool ret = deviceTest->DeleteDeviceInfo(udid);
    udid = "DeleteDeviceInfo";
    ret = deviceTest->DeleteDeviceInfo(udid);
    EXPECT_EQ(ret, true);
    deviceTest->Stop();
}

HWTEST_F(MediaLibraryDeviceTest, medialib_GetMediaLibraryDeviceInfo_test_001, TestSize.Level0)
{
    shared_ptr<MediaLibraryDevice> deviceTest = MediaLibraryDevice::GetInstance();
    EXPECT_NE(deviceTest, nullptr);
    deviceTest->Start();
    DistributedHardware::DmDeviceInfo dmInfo;
    dmInfo.networkId[0] = 'a';
    dmInfo.deviceName[0] = 'a';
    dmInfo.deviceTypeId = 1;
    MediaLibraryDeviceInfo mlInfo;
    deviceTest->GetMediaLibraryDeviceInfo(dmInfo, mlInfo);
    deviceTest->Stop();
}

HWTEST_F(MediaLibraryDeviceTest, medialib_QueryDeviceTable_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    shared_ptr<MediaLibraryDevice> deviceTest = MediaLibraryDevice::GetInstance();
    deviceTest->Start();
    bool ret = deviceTest->QueryDeviceTable();
    EXPECT_EQ(ret, true);
    deviceTest->Stop();
}

HWTEST_F(MediaLibraryDeviceTest, medialib_ClearAllDevices_test_001, TestSize.Level0)
{
    shared_ptr<MediaLibraryDevice> deviceTest = MediaLibraryDevice::GetInstance();
    EXPECT_NE(deviceTest, nullptr);
    deviceTest->Start();
    deviceTest->ClearAllDevices();
    deviceTest->Stop();
}

HWTEST_F(MediaLibraryDeviceTest, medialib_IsHasDevice_test_001, TestSize.Level0)
{
    shared_ptr<MediaLibraryDevice> deviceTest = MediaLibraryDevice::GetInstance();
    EXPECT_NE(deviceTest, nullptr);
    deviceTest->Start();
    string deviceUdid = "";
    bool ret = deviceTest->IsHasDevice(deviceUdid);
    EXPECT_EQ(ret, false);
    deviceUdid = "IsHasDevice";
    ret = deviceTest->IsHasDevice(deviceUdid);
    EXPECT_EQ(ret, false);
    deviceTest->Stop();
}

HWTEST_F(MediaLibraryDeviceTest, medialib_RegisterToDM_test_001, TestSize.Level0)
{
    shared_ptr<MediaLibraryDevice> deviceTest = MediaLibraryDevice::GetInstance();
    EXPECT_NE(deviceTest, nullptr);
    deviceTest->Start();
    deviceTest->RegisterToDM();
    deviceTest->Stop();
}

HWTEST_F(MediaLibraryDeviceTest, medialib_UnRegisterFromDM_test_001, TestSize.Level0)
{
    shared_ptr<MediaLibraryDevice> deviceTest = MediaLibraryDevice::GetInstance();
    EXPECT_NE(deviceTest, nullptr);
    deviceTest->Start();
    deviceTest->UnRegisterFromDM();
    deviceTest->Stop();
}

HWTEST_F(MediaLibraryDeviceTest, medialib_DevOnlineProcess_test_001, TestSize.Level0)
{
    shared_ptr<MediaLibraryDevice> deviceTest = MediaLibraryDevice::GetInstance();
    EXPECT_NE(deviceTest, nullptr);
    deviceTest->Start();
    DistributedHardware::DmDeviceInfo devInfo;
    deviceTest->DevOnlineProcess(devInfo);
    deviceTest->Stop();
}

HWTEST_F(MediaLibraryDeviceTest, medialib_TryToGetTargetDevMLInfos_test_001, TestSize.Level0)
{
    shared_ptr<MediaLibraryDevice> deviceTest = MediaLibraryDevice::GetInstance();
    EXPECT_NE(deviceTest, nullptr);
    string udid = "TryToGetTargetDevMLInfos";
    string networkId = "Test";
    deviceTest->TryToGetTargetDevMLInfos(udid, networkId);
    deviceTest->Start();
    deviceTest->TryToGetTargetDevMLInfos(udid, networkId);
    deviceTest->Stop();
}

HWTEST_F(MediaLibraryDeviceTest, medialib_IsHasActiveDevice_test_001, TestSize.Level0)
{
    shared_ptr<MediaLibraryDevice> deviceTest = MediaLibraryDevice::GetInstance();
    bool ret = deviceTest->IsHasActiveDevice();
    EXPECT_EQ(ret, false);
    deviceTest->Start();
    ret = deviceTest->IsHasActiveDevice();
    EXPECT_EQ(ret, false);
    deviceTest->Stop();
}
} // namespace Media
} // namespace OHOS