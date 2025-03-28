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

#ifndef OHOS_MEDIA_IPC_USER_DEFINE_IPC_H
#define OHOS_MEDIA_IPC_USER_DEFINE_IPC_H

#include <string>

#include "message_parcel.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "media_req_vo.h"
#include "media_resp_vo.h"
#include "media_empty_obj_vo.h"

namespace OHOS::Media::IPC {
class UserDefineIPC {
public:
    template <class REQ>
    int32_t ReadRequestBody(MessageParcel &data, REQ &reqBody)
    {
        IPC::MediaReqVo<REQ> *reqVoPtr = IPC::MediaReqVo<REQ>::Unmarshalling(data);
        bool errConn = reqVoPtr == nullptr;
        CHECK_AND_RETURN_RET_LOG(!errConn, E_IPC_SEVICE_UNMARSHALLING_FAIL, "Failed to unmarshalling data");
        reqBody = reqVoPtr->GetBody();
        delete reqVoPtr;
        return E_OK;
    }

    template <class RSP>
    void WriteResponseBody(MessageParcel &reply, const RSP &reqBody, const int32_t errCode = E_OK)
    {
        IPC::MediaRespVo<RSP> respVo;
        respVo.SetBody(reqBody);
        respVo.SetErrCode(errCode);
        bool errConn = !respVo.Marshalling(reply);
        CHECK_AND_PRINT_LOG(!errConn, "Failed to marshalling data");
        return;
    }

    void WriteResponseBody(MessageParcel &reply, const int32_t errCode = E_OK)
    {
        WriteResponseBody(reply, IPC::MediaEmptyObjVo(), errCode);
        return;
    }
};
}  // namespace OHOS::Media::IPC
#endif  // OHOS_MEDIA_IPC_USER_DEFINE_IPC_H