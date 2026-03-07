/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define MLOG_TAG "Media_Cloud_Int64Fields_Test"

#include "cloud_int64_fields_hash_map_test.h"

#include "cloud_file_data_convert.h"
#include "cloud_mdkrecord_photos_vo.h"
#include "mdk_record_photos_data.h"
#include "on_fetch_photos_vo.h"
#include "cloud_media_photo_controller_processor.h"
#include "cloud_media_pull_data_dto.h"
#include "cloud_sync_convert.h"
#include "medialibrary_errno.h"

using namespace testing::ext;

namespace OHOS::Media::CloudSync {

void CloudInt64FieldsHashMapTest::SetUpTestCase()
{}
void CloudInt64FieldsHashMapTest::TearDownTestCase()
{}
void CloudInt64FieldsHashMapTest::SetUp()
{}
void CloudInt64FieldsHashMapTest::TearDown()
{}

HWTEST_F(CloudInt64FieldsHashMapTest, HandleInt64FieldsHashMap_Normal, TestSize.Level1)
{
    CloudFileDataConvert convert(FILE_CREATE, 100);
    CloudMdkRecordPhotosVo uploadRecord;
    uploadRecord.int64fields["test_field1"] = 123456789;
    uploadRecord.int64fields["test_field2"] = 987654321;

    std::map<std::string, MDKRecordField> data;
    int32_t ret = convert.HandleInt64FieldsHashMap(data, uploadRecord);

    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(data.size(), 2);
    EXPECT_TRUE(data.find("test_field1") != data.end());
    EXPECT_TRUE(data.find("test_field2") != data.end());
}

HWTEST_F(CloudInt64FieldsHashMapTest, HandleInt64FieldsHashMap_Empty, TestSize.Level1)
{
    CloudFileDataConvert convert(FILE_CREATE, 100);
    CloudMdkRecordPhotosVo uploadRecord;

    std::map<std::string, MDKRecordField> data;
    int32_t ret = convert.HandleInt64FieldsHashMap(data, uploadRecord);

    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(data.size(), 0);
}

HWTEST_F(CloudInt64FieldsHashMapTest, GetInt64FieldsHashMap_Normal, TestSize.Level1)
{
    CloudMediaPhotoControllerProcessor processor;
    PhotosPo record;
    record.attributes["test_field1"] = "123456789";
    record.attributes["test_field2"] = "987654321";

    CloudMdkRecordPhotosVo photosVo;
    bool ret = processor.GetInt64FieldsHashMap(record, photosVo);

    EXPECT_TRUE(ret);
    // fields (test_field1, test_field2) are not included in PHOTOS_SYNC_COLUMN_INT64.
    EXPECT_TRUE(photosVo.int64fields.empty());
}

HWTEST_F(CloudInt64FieldsHashMapTest, CompensateInt64FieldsHashMap_Normal, TestSize.Level1)
{
    CloudMediaPullDataDto data;
    data.int64fields["test_field1"] = 123456789;
    data.int64fields["test_field2"] = 987654321;

    NativeRdb::ValuesBucket values;
    int32_t ret = CloudSyncConvert::CompensateInt64FieldsHashMap(data, values);

    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(values.HasColumn("test_field1"));
    EXPECT_TRUE(values.HasColumn("test_field2"));
}

HWTEST_F(CloudInt64FieldsHashMapTest, CompensateInt64FieldsHashMap_Empty, TestSize.Level1)
{
    CloudMediaPullDataDto data;

    NativeRdb::ValuesBucket values;
    int32_t ret = CloudSyncConvert::CompensateInt64FieldsHashMap(data, values);

    EXPECT_EQ(ret, E_OK);
}

}  // namespace OHOS::Media::CloudSync
