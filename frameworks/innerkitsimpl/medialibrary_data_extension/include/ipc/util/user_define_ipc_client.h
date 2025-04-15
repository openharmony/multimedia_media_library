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

#ifndef OHOS_MEDIA_IPC_USER_DEFINE_IPC_CLIENT_H
#define OHOS_MEDIA_IPC_USER_DEFINE_IPC_CLIENT_H

#include <string>

#include "message_parcel.h"
#include "userfile_client.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "media_req_vo.h"
#include "media_resp_vo.h"
#include "media_empty_obj_vo.h"

namespace OHOS::Media::IPC {
class UserDefineIPCClient {
private:
    int32_t InitClient();
    int32_t HeaderMarshalling(MessageParcel &data, uint32_t code);

private:
    template <class REQ>
    int32_t BodyMarshalling(MessageParcel &data, const REQ &reqBody)
    {
        MediaReqVo<REQ> reqVo;
        reqVo.SetBody(reqBody);
        bool errConn = !reqVo.Marshalling(data);
        CHECK_AND_RETURN_RET_LOG(!errConn, E_IPC_INVAL_ARG, "Failed to Marshalling");
        return E_OK;
    }
    template <class RSP>
    int32_t BodyUnmarshalling(MessageParcel &reply, RSP &respBody, int32_t &errCode)
    {
        MediaRespVo<RSP> *respVoPtr = MediaRespVo<RSP>::Unmarshalling(reply);
        bool errConn = respVoPtr == nullptr;
        CHECK_AND_RETURN_RET_LOG(!errConn, E_IPC_INVAL_ARG, "Failed to UnMarshalling");
        respBody = respVoPtr->GetBody();
        errCode = respVoPtr->GetErrCode();
        delete respVoPtr;
        return E_OK;
    }

public:
    template <class REQ, class RSP>
    int32_t Call(uint32_t code, const REQ &reqBody, RSP &respBody)
    {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;
        int32_t ret = this->HeaderMarshalling(data, code);
        bool errConn = ret != E_OK;
        CHECK_AND_RETURN_RET(!errConn, ret);
        // user define request data.
        ret = this->BodyMarshalling<REQ>(data, reqBody);
        errConn = ret != E_OK;
        CHECK_AND_RETURN_RET(!errConn, ret);
        ret = this->InitClient();
        errConn = ret != E_OK;
        CHECK_AND_RETURN_RET(!errConn, ret);
        // post user define request to service.
        ret = UserFileClient::UserDefineFunc(data, reply, option);
        errConn = ret != E_OK;
        CHECK_AND_RETURN_RET_LOG(
            !errConn, ret, "Failed to connect Server, error code: %{public}d, func: %{public}u", ret, code);
        // user define response data.
        int32_t errCode = E_OK;
        ret = this->BodyUnmarshalling<RSP>(reply, respBody, errCode);
        errConn = ret != E_OK;
        CHECK_AND_RETURN_RET(!errConn, ret);
        return errCode;
    }
    template <class REQ>
    int32_t Call(uint32_t code, const REQ &reqBody)
    {
        MediaEmptyObjVo respBody;
        return Call<REQ, MediaEmptyObjVo>(code, reqBody, respBody);
    }
    int32_t Call(uint32_t code)
    {
        MediaEmptyObjVo respBody;
        return Call<MediaEmptyObjVo, MediaEmptyObjVo>(code, MediaEmptyObjVo(), respBody);
    }
};
}  // namespace OHOS::Media::IPC
#endif  // OHOS_MEDIA_IPC_USER_DEFINE_IPC_CLIENT_H