/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_ACCURATE_COMMON_DATA_H
#define OHOS_MEDIALIBRARY_ACCURATE_COMMON_DATA_H

#include <string>
#include "parcel.h"

namespace OHOS {
namespace Media::AccurateRefresh {

const std::string EMPTY_STR = "";
const int32_t INVALID_INT32_VALUE = -1;
const int64_t INVALID_INT64_VALUE = -1;

const int32_t ACCURATE_REFRESH_RET_OK = 0;

const int32_t ACCURATE_REFRESH_BASE = 0x10000;

// 入参错误
const int32_t ACCURATE_REFRESH_INPUT_PARA_ERR = ACCURATE_REFRESH_BASE + 1;

// rdb
const int32_t ACCURATE_REFRESH_RDB_NULL = ACCURATE_REFRESH_BASE + 2;

// AssetDataManager/AlbumDataManager 类异常返回值
const int32_t ACCURATE_REFRESH_DATA_MGR_BASE = 0x20000;
// 查出变化数据为空
const int32_t ACCURATE_REFRESH_MODIFY_EMPTY = ACCURATE_REFRESH_DATA_MGR_BASE + 1;

// 变化后数据存在，修改前数据不存在
const int32_t ACCURATE_REFRESH_MODIFY_ABNORMAL = ACCURATE_REFRESH_DATA_MGR_BASE + 2;

// 变化前后不匹配
const int32_t ACCURATE_REFRESH_MODIFY_NO_MATCH = ACCURATE_REFRESH_DATA_MGR_BASE + 3;

// 非ADD场景，initDatas为空
const int32_t ACCURATE_REFRESH_INIT_EMPTY = ACCURATE_REFRESH_DATA_MGR_BASE + 4;

// 计算后的changeDatas数据为空
const int32_t ACCURATE_REFRESH_CHANGE_DATA_EMPTY = ACCURATE_REFRESH_DATA_MGR_BASE + 5;

// dataManager为null，使用流程错误
const int32_t ACCURATE_REFRESH_DATA_MGR_NULL = ACCURATE_REFRESH_DATA_MGR_BASE + 6;

// 待更新相册和查询出来的数据不一致
const int32_t ACCURATE_REFRESH_ALBUM_NO_MATCH = ACCURATE_REFRESH_DATA_MGR_BASE + 7;

// 系统相册全量更新
const int32_t ACCURATE_REFRESH_ALBUM_ALL = ACCURATE_REFRESH_DATA_MGR_BASE + 8;

// 插入Init数据重复
const int32_t ACCURATE_REFRESH_INIT_REPEAT = ACCURATE_REFRESH_DATA_MGR_BASE + 9;

// 插入Modified数据重复
const int32_t ACCURATE_REFRESH_MODIFIED_REPEAT = ACCURATE_REFRESH_DATA_MGR_BASE + 10;

// Add场景init已存在数据
const int32_t ACCURATE_REFRESH_MODIFIED_ADD_NO_MATCH = ACCURATE_REFRESH_DATA_MGR_BASE + 11;

// Update/Del场景没有init数据
const int32_t ACCURATE_REFRESH_MODIFIED_NO_INIT = ACCURATE_REFRESH_DATA_MGR_BASE + 12;

// 对同一key做operation处理，但是操作不匹配（除了增改和改改之外的操作）
const int32_t ACCURATE_REFRESH_OPERATION_NO_MATCH = ACCURATE_REFRESH_DATA_MGR_BASE + 13;

// notifyExe_为null，使用流程错误
const int32_t ACCURATE_REFRESH_NOTIFY_EXE_NULL = ACCURATE_REFRESH_DATA_MGR_BASE + 14;

// ForceUpdateAlbumInfo更新找不到数据
const int32_t ACCURATE_REFRESH_ALBUM_INFO_NULL = ACCURATE_REFRESH_DATA_MGR_BASE + 15;

// 数据库类异常返回值
const int32_t ACCURATE_REFRESH_RDB_BASE = 0x40000;
const int32_t ACCURATE_REFRESH_RDB_INSERT_ERR = ACCURATE_REFRESH_RDB_BASE + 1;

const int32_t ACCURATE_REFRESH_RDB_INVALITD_TABLE = ACCURATE_REFRESH_RDB_BASE + 2;

enum RdbOperation {
    RDB_OPERATION_UNDEFINED,
    RDB_OPERATION_ADD,
    RDB_OPERATION_REMOVE,
    RDB_OPERATION_UPDATE,
};

template <typename ChangeInfo>
class AccurateRefreshChangeData : public Parcelable {
public:
    std::string ToString() const
    {
        return "info before: " + infoBeforeChange_.ToString(true) + "; info after: " +
        infoAfterChange_.ToString((true)) + ", isDelete_: " + std::to_string(isDelete_) +
        ", operation_: " + std::to_string(operation_) + ", version_: " + std::to_string(version_);
    }
    bool Marshalling(Parcel &parcel) const override
    {
        return Marshalling(parcel, false);
    }
    bool Marshalling(Parcel &parcel, bool isSystem) const
    {
        bool ret = infoBeforeChange_.Marshalling(parcel, isSystem);
        ret = ret && infoAfterChange_.Marshalling(parcel, isSystem);
        ret = ret && parcel.WriteBool(isDelete_);
        ret = ret && parcel.WriteInt32(static_cast<int32_t>(operation_));
        ret = ret && parcel.WriteBool(isSystem);
        if (isSystem) {
            ret = ret && parcel.WriteInt64(version_);
        }
        return ret;
    }

    virtual bool ReadFromParcel(Parcel &parcel)
    {
        bool ret = infoBeforeChange_.ReadFromParcel(parcel);
        ret = ret && infoAfterChange_.ReadFromParcel(parcel);
        ret = ret && parcel.ReadBool(isDelete_);
        int32_t operationNum;
        if (parcel.ReadInt32(operationNum)) {
            operation_ = static_cast<RdbOperation>(operationNum);
        } else {
            return false;
        }
        ret = ret && parcel.ReadBool(isSystem_);
        if (isSystem_) {
            ret = ret && parcel.ReadInt64(version_);
        }
        return ret;
    }
public:
    ChangeInfo infoBeforeChange_;
    ChangeInfo infoAfterChange_;
    bool isDelete_ = false;
    RdbOperation operation_ = RDB_OPERATION_UNDEFINED;
    int64_t version_ = INVALID_INT64_VALUE;

protected:
    bool isSystem_ = false;
};

} // namespace Media
} // namespace OHOS

#endif