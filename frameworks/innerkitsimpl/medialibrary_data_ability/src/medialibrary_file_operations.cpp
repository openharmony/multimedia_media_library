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

#include "medialibrary_file_operations.h"
#include "media_log.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
int32_t MediaLibraryFileOperations::HandleCreateAsset(const ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore)
{
    string path;
    int32_t errCode = DATA_ABILITY_FAIL;

    ValueObject valueObject;

    FileAsset fileAsset;
    MediaLibraryFileDb fileDbOprn;

    auto contains = values.GetObject(MEDIA_DATA_DB_FILE_PATH, valueObject);
    if (contains) {
        valueObject.GetString(path);
    }

    errCode = fileAsset.CreateAsset(path);
    if (errCode == DATA_ABILITY_SUCCESS) {
        // will return row id
        errCode = fileDbOprn.Insert(values, rdbStore);
    }

    return errCode;
}

int32_t MediaLibraryFileOperations::HandleCloseAsset(string &srcPath, const ValuesBucket &values)
{
    int32_t fd(-1);
    ValueObject valueObject;
    FileAsset fileAsset;

    auto contains = values.GetObject(MEDIA_FILEDESCRIPTOR, valueObject);
    if (contains) {
        valueObject.GetInt(fd);
    }

    int32_t res = fileAsset.CloseAsset(fd);
    if (res == SUCCESS) {
        auto client = MediaScannerHelperFactory::CreateScannerHelper();
        if (client) {
            std::shared_ptr<ScanFileCallback> scanFileCb = make_shared<ScanFileCallback>();
            (void)client->ScanFile(srcPath, scanFileCb);
        }
    }

    return res;
}

int32_t MediaLibraryFileOperations::HandleOpenAsset(const string &srcPath, const ValuesBucket &values)
{
    FileAsset fileAsset;
    string mode;

    ValueObject valueObject;
    auto contains = values.GetObject(MEDIA_FILEMODE, valueObject);
    if (contains) {
        valueObject.GetString(mode);
    }

    return fileAsset.OpenAsset(srcPath, mode);
}

int32_t MediaLibraryFileOperations::HandleModifyAsset(const string &rowNum, const string &srcPath,
    const ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore)
{
    string dstPath;
    string dstFileName;
    int32_t errCode = DATA_ABILITY_FAIL;
    ValueObject valueObject;

    FileAsset fileAsset;
    MediaLibraryFileDb fileDbOprn;

    auto contains = values.GetObject(MEDIA_DATA_DB_NAME, valueObject);
    if (contains) {
        valueObject.GetString(dstFileName);
    }

    size_t slashIndex = srcPath.rfind("/");
    if (slashIndex != string::npos) {
        dstPath = srcPath.substr(0, slashIndex) + "/" + dstFileName;
    }

    errCode = fileAsset.ModifyAsset(srcPath, dstPath);
    if (errCode == DATA_ABILITY_SUCCESS) {
        errCode = fileDbOprn.Modify(rowNum, dstPath, rdbStore);
    }

    return errCode;
}

int32_t MediaLibraryFileOperations::HandleDeleteAsset(const string &rowNum, const string &srcPath,
    const shared_ptr<RdbStore> &rdbStore)
{
    int32_t errCode = DATA_ABILITY_FAIL;
    FileAsset fileAsset;
    MediaLibraryFileDb fileDbOprn;

    errCode = fileAsset.DeleteAsset(srcPath);
    if (errCode == DATA_ABILITY_SUCCESS) {
        errCode = fileDbOprn.Delete(rowNum, rdbStore);
    }

    return errCode;
}

int32_t MediaLibraryFileOperations::HandleFileOperation(const string &uri, const ValuesBucket &values,
    const shared_ptr<RdbStore> &rdbStore)
{
    int32_t errCode = DATA_ABILITY_FAIL;
    string actualUri;
    ValueObject valueObject;
    MediaLibraryFileDb fileDbOprn;

    size_t found = uri.rfind('/');
    if (found != string::npos) {
        string oprn = uri.substr(found + 1);
        if (oprn == MEDIA_FILEOPRN_CREATEASSET) {
            return HandleCreateAsset(values, rdbStore);
        }

        auto contains = values.GetObject(MEDIA_DATA_DB_URI, valueObject);
        if (contains) {
            valueObject.GetString(actualUri);
        }
        string rowNum = GetRowNum(actualUri);
        string srcPath = fileDbOprn.QueryFilePath(rowNum, rdbStore);

        if (oprn == MEDIA_FILEOPRN_OPENASSET) {
            errCode = HandleOpenAsset(srcPath, values);
        } else if (oprn == MEDIA_FILEOPRN_MODIFYASSET) {
            errCode = HandleModifyAsset(rowNum, srcPath, values, rdbStore);
        } else if (oprn == MEDIA_FILEOPRN_DELETEASSET) {
            errCode = HandleDeleteAsset(rowNum, srcPath, rdbStore);
        } else if (oprn == MEDIA_FILEOPRN_CLOSEASSET) {
            return HandleCloseAsset(srcPath, values);
        }
    }

    return errCode;
}

string MediaLibraryFileOperations::GetRowNum(string uri)
{
    string rowNum = "-1";

    size_t pos = uri.rfind('/');
    if (pos != std::string::npos) {
        rowNum = uri.substr(pos + 1);
    }

    return rowNum;
}

void ScanFileCallback::OnScanFinished(const int32_t status, const std::string &uri, const std::string &path)
{
}
} // namespace Media
} // namespace OHOS