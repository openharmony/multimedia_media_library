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
#include "mtp_error_utils.h"
#include <map>

#include "medialibrary_errno.h"
#include "media_log.h"
#include "media_mtp_utils.h"
#include "mtp_constants.h"

using namespace std;
namespace OHOS {
namespace Media {
namespace {
static const std::map<int32_t, int32_t> getHandlesError = {
    { E_SUCCESS, MTP_SUCCESS },
    { E_HAS_DB_ERROR, MTP_ERROR_STORE_NOT_AVAILABLE },
    { E_NO_SUCH_FILE, MTP_ERROR_INVALID_OBJECTHANDLE },
};
static const std::map<int32_t, int32_t> getObjectInfoError = {
    { E_SUCCESS, MTP_SUCCESS },
    { E_HAS_DB_ERROR, MTP_ERROR_STORE_NOT_AVAILABLE },
    { E_NO_SUCH_FILE, MTP_ERROR_INVALID_OBJECTHANDLE },
};
static const std::map<int32_t, int32_t> getFdInfoError = {
    { E_SUCCESS, MTP_SUCCESS },
    { E_HAS_DB_ERROR, MTP_ERROR_STORE_NOT_AVAILABLE },
    { E_HAS_FS_ERROR, MTP_ERROR_INVALID_OBJECTHANDLE },
};
static const std::map<int32_t, int32_t> sendObjectInfoError = {
    { E_SUCCESS, MTP_SUCCESS },
    { E_HAS_DB_ERROR, MTP_ERROR_STORE_NOT_AVAILABLE },
    { E_NO_SUCH_FILE, MTP_ERROR_INVALID_PARENTOBJECT },
};
static const std::map<int32_t, int32_t> moveObjectError = {
    { E_SUCCESS, MTP_SUCCESS },
    { E_HAS_DB_ERROR, MTP_ERROR_STORE_NOT_AVAILABLE },
    { E_NO_SUCH_FILE, MTP_ERROR_INVALID_OBJECTHANDLE },
    { E_INVALID_FILEID, MTP_ERROR_INVALID_OBJECTHANDLE },
    { E_INVALID_PATH, MTP_ERROR_INVALID_OBJECTHANDLE },
    { E_MODIFY_DATA_FAIL, MTP_ERROR_INVALID_OBJECTHANDLE },
    { E_FAIL, MTP_ERROR_PARAMETER_NOT_SUPPORTED },
    { E_FILE_EXIST, MTP_ERROR_PARAMETER_NOT_SUPPORTED },
    { E_FILE_OPER_FAIL, MTP_ERROR_STORE_NOT_AVAILABLE },
};
static const std::map<int32_t, int32_t> copyObjectError = {
    { E_SUCCESS, MTP_SUCCESS },
    { E_HAS_DB_ERROR, MTP_ERROR_INVALID_OBJECTHANDLE },
    { E_NO_SUCH_FILE, MTP_ERROR_INVALID_OBJECTHANDLE },
    { E_INVALID_FILEID, MTP_ERROR_INVALID_OBJECTHANDLE },
    { E_INVALID_PATH, MTP_ERROR_INVALID_OBJECTHANDLE },
    { E_FAIL, MTP_ERROR_PARAMETER_NOT_SUPPORTED },
    { E_FILE_EXIST, MTP_ERROR_PARAMETER_NOT_SUPPORTED },
    { E_VIOLATION_PARAMETERS, MTP_ERROR_PARAMETER_NOT_SUPPORTED },
    { E_DELETE_DIR_FAIL, MTP_ERROR_INVALID_OBJECTHANDLE },
};
static const std::map<int32_t, int32_t> deleteObjectError = {
    { E_SUCCESS, MTP_SUCCESS },
    { E_HAS_DB_ERROR, MTP_ERROR_INVALID_OBJECTHANDLE },
    { E_FAIL, MTP_ERROR_PARAMETER_NOT_SUPPORTED },
    { E_NO_SUCH_FILE, MTP_ERROR_INVALID_OBJECTHANDLE },
    { E_VIOLATION_PARAMETERS, MTP_ERROR_PARAMETER_NOT_SUPPORTED },
};
static const std::map<int32_t, int32_t> objectPropValueError = {
    { E_SUCCESS, MTP_SUCCESS },
    { E_HAS_DB_ERROR, MTP_ERROR_INVALID_OBJECTPROP_FORMAT },
    { E_NO_SUCH_FILE, MTP_ERROR_INVALID_OBJECTPROPCODE },
    { E_INVALID_FILEID, MTP_ERROR_INVALID_OBJECTPROP_VALUE },
    { E_INVALID_PATH, MTP_ERROR_INVALID_OBJECTPROP_VALUE },
    { E_MODIFY_DATA_FAIL, MTP_ERROR_INVALID_OBJECTPROPCODE },
    { E_FAIL, MTP_ERROR_INVALID_OBJECTPROPCODE },
    { E_FILE_EXIST, MTP_ERROR_INVALID_OBJECTPROPCODE },
    { E_FILE_OPER_FAIL, MTP_ERROR_INVALID_OBJECTPROPCODE },
};
static const std::map<int32_t, int32_t> CloseFdError = {
    { E_SUCCESS, MTP_SUCCESS },
    { E_HAS_DB_ERROR, MTP_ERROR_STORE_NOT_AVAILABLE },
    { E_INVALID_FILEID, MTP_ERROR_INVALID_OBJECTHANDLE },
};
} // namespace

static inline int32_t SolveError(const int32_t mediaError, const std::map<int32_t, int32_t> &errorMap,
    int32_t defaultError)
{
    auto it = errorMap.find(mediaError);
    if (it != errorMap.end()) {
        return it->second;
    }
    return defaultError;
}
int32_t MtpErrorUtils::SolveGetHandlesError(const int32_t mediaError)
{
    return SolveError(mediaError, getHandlesError, MTP_ERROR_INVALID_OBJECTHANDLE);
}

int32_t MtpErrorUtils::SolveGetObjectInfoError(const int32_t mediaError)
{
    return SolveError(mediaError, getObjectInfoError, MTP_ERROR_INVALID_OBJECTHANDLE);
}

int32_t MtpErrorUtils::SolveGetFdError(const int32_t mediaError)
{
    return SolveError(mediaError, getFdInfoError, MTP_ERROR_INVALID_OBJECTHANDLE);
}

int32_t MtpErrorUtils::SolveSendObjectInfoError(const int32_t mediaError)
{
    return SolveError(mediaError, sendObjectInfoError, MTP_ERROR_INVALID_OBJECTHANDLE);
}

int32_t MtpErrorUtils::SolveMoveObjectError(const int32_t mediaError)
{
    return SolveError(mediaError, moveObjectError, MTP_ERROR_INVALID_OBJECTHANDLE);
}

int32_t MtpErrorUtils::SolveCopyObjectError(const int32_t mediaError)
{
    return SolveError(mediaError, copyObjectError, MTP_ERROR_INVALID_OBJECTHANDLE);
}

int32_t MtpErrorUtils::SolveDeleteObjectError(const int32_t mediaError)
{
    return SolveError(mediaError, deleteObjectError, MTP_ERROR_INVALID_OBJECTHANDLE);
}

int32_t MtpErrorUtils::SolveObjectPropValueError(const int32_t mediaError)
{
    return SolveError(mediaError, objectPropValueError, MTP_ERROR_INVALID_OBJECTPROPCODE);
}

int32_t MtpErrorUtils::SolveCloseFdError(const int32_t mediaError)
{
    return SolveError(mediaError, CloseFdError, MTP_ERROR_INVALID_OBJECTHANDLE);
}
} // namespace Media
} // namespace OHOS