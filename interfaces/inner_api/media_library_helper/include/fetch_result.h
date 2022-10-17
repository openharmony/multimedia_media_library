/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_FETCH_RESULT_H_
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_FETCH_RESULT_H_

#include <variant>
#include "abs_shared_result_set.h"
#include "album_asset.h"
#include "datashare_result_set.h"
#include "file_asset.h"
#include "medialibrary_type_const.h"
#include "medialibrary_db_const.h"
#include "rdb_errno.h"
#include "smart_album_asset.h"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
enum ResultSetDataType {
    TYPE_NULL = 0,
    TYPE_STRING,
    TYPE_INT32,
    TYPE_INT64,
    TYPE_DOUBLE
};

/**
 * @brief Class for returning the data cursor to application.
 *
 * @since 1.0
 * @version 1.0
 */
template <class T>
class FetchResult {
public:
    explicit FetchResult(const std::shared_ptr<DataShare::DataShareResultSet> &resultset);
    FetchResult();
    virtual ~FetchResult();

    void Close();
    int32_t GetCount();
    bool IsContain();
    bool IsClosed();
    bool IsAtLastRow();
    void SetInfo(unique_ptr<FetchResult<T>> &fetch);
    void SetNetworkId(const string &networkId);
    std::unique_ptr<T> GetObjectAtPosition(int32_t index);
    std::unique_ptr<T> GetFirstObject();
    std::unique_ptr<T> GetObjectFromRdb(std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet, int idx);
    std::unique_ptr<T> GetNextObject();
    std::unique_ptr<T> GetLastObject();
    std::unique_ptr<T> GetObject();

    bool isContain_;
    bool isClosed_;
    int32_t count_;
    std::string networkId_;
    ResultNapiType resultNapiType_;
    std::shared_ptr<DataShare::DataShareResultSet> resultset_ = nullptr;
    FetchResType fetchResType_;
    std::string typeMask_;

private:
    std::unique_ptr<T> GetObject(std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet);
    std::variant<int32_t, int64_t, std::string> GetRowValFromColumn(std::string columnName,
        ResultSetDataType dataType, std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet);
    std::variant<int32_t, int64_t, string> GetValByIndex(int32_t index, ResultSetDataType dataType,
        std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet);
    int32_t GetFileCount(const std::shared_ptr<DataShare::DataShareResultSet> &resultSet);
    void SetFileAsset(FileAsset *fileAsset, std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet);
    void SetAlbumAsset(AlbumAsset* albumData, std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet);
    void SetSmartAlbumAsset(SmartAlbumAsset* smartAlbumData, std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet);
    void GetObjectFromAsset(FileAsset *asset, shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet);
    void GetObjectFromAsset(AlbumAsset *asset, shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet);
    void GetObjectFromAsset(SmartAlbumAsset *asset, shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet);
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_INNERKITS_NATIVE_INCLUDE_FETCH_RESULT_H_