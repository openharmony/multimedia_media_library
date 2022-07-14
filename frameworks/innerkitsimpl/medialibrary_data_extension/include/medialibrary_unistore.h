/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_UNISTORE_H
#define OHOS_MEDIALIBRARY_UNISTORE_H

#include "ability_context.h"
#include "medialibrary_command.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "rdb_types.h"

namespace OHOS {
namespace Media {
class MediaLibraryUnistore {
public:
    MediaLibraryUnistore() = default;
    virtual ~MediaLibraryUnistore() = default;

    virtual void Init() = 0;
    virtual void Stop() = 0;

    virtual int32_t Insert(MediaLibraryCommand &cmd, int64_t &rowId) = 0;
    virtual int32_t Delete(MediaLibraryCommand &cmd, int32_t &rowId) = 0;
    virtual int32_t Update(MediaLibraryCommand &cmd, int32_t &rowId) = 0;
    virtual std::shared_ptr<NativeRdb::AbsSharedResultSet> Query(MediaLibraryCommand &cmd,
        const std::vector<std::string> &columns)
    {
        return nullptr;
    }

    virtual bool SyncPullAllTableByDeviceId(const std::string &bundleName, std::vector<std::string> &devices)
    {
        return false;
    }

    virtual bool SyncPullTable(const std::string &bundleName, const std::string &tableName,
        const std::vector<std::string> &devices, bool isLast = false)
    {
        return false;
    }

    virtual bool SyncPushTable(const std::string &bundleName, const std::string &tableName,
        const std::vector<std::string> &devices, bool isBlock = false)
    {
        return false;
    }

    virtual int32_t ExecuteSql(const std::string &sql)
    {
        return NativeRdb::E_NOT_SUPPORT;
    }

    virtual std::shared_ptr<NativeRdb::AbsSharedResultSet> QuerySql(const std::string &sql)
    {
        return nullptr;
    }

    virtual std::string ObtainTableName(MediaLibraryCommand &cmd)
    {
        return "";
    }
};
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_UNISTORE_H
