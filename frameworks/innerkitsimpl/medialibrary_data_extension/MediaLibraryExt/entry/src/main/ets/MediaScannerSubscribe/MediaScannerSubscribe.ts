import StaticSubscriberExtensionAbility from '@ohos.application.StaticSubscriberExtensionAbility'
import rpc from '@ohos.rpc'
import mediaLibrary from '@ohos.multimedia.mediaLibrary';

const BUNDLE_NAME = "com.ohos.medialibrary.medialibrarydata";
const SERVICE_EXT_ABILITY_NAME = "MediaDataService"
const REQUEST_CODE = 1;
const ERROR_CODE = -1;
const SUCCESS_CODE = 1;

class ScannerMessaageClient {
    connection = -1;
    firstLocalValue = 0;
    secondLocalValue = 0;
    remoteCallback = null;
    context = null;
    options = null;
    constructor() {
        this.context = globalThis.mainAbilityContext;
        this.options = {
            outObj: this,
            onConnect: function (elementName, proxy) {
                console.log("[MediaScannerSubscriber] onConnect success");
                if (proxy == null) {
                    console.log("[MediaScannerSubscriber] onConnect proxy is null");
                    return;
                }
                let option = new rpc.MessageOption();
                let data = new rpc.MessageParcel();
                let reply = new rpc.MessageParcel();
                data.writeInt(this.outObj.firstLocalValue);
                data.writeInt(this.outObj.secondLocalValue);
                proxy.sendRequest(REQUEST_CODE, data, reply, option).then((result) => {
                    console.log("[MediaScannerSubscriber] sendRequest: " + result);
                    let msg = reply.readInt();
                    console.log("[MediaScannerSubscriber] sendRequest:msg: " + msg);
                }).catch((e) => {
                    console.log("[MediaScannerSubscriber] error sendRequest error: " + e);
                });
            },
            onDisconnect: function () {
                console.log("[MediaScannerSubscriber] onDisconnect");
            },
            onFailed: function () {
                console.log("[MediaScannerSubscriber] onFailed");
            }
        }
    }

    startServiceExtAbility(callback) {
        console.log("[MediaScannerSubscriber] startServiceExtAbility");
        let want = {
            bundleName: BUNDLE_NAME,
            abilityName: SERVICE_EXT_ABILITY_NAME
        };
        this.context.startAbility(want).then((data) => {
            console.log("[MediaScannerSubscriber] startAbility success: " + data);
            callback(SUCCESS_CODE);
        }).catch((error) => {
            console.log("[MediaScannerSubscriber] startAbility failed: " + error);
            callback(ERROR_CODE);
        })
    }

    connectServiceExtAbility(fir, sec, callback) {
        console.log("[MediaScannerSubscriber] connectServiceExtAbility");
        this.firstLocalValue = fir;
        this.secondLocalValue = sec;
        this.remoteCallback = callback;
        let want = {
            bundleName: BUNDLE_NAME,
            abilityName: SERVICE_EXT_ABILITY_NAME
        };
        this.connection = this.context.connectAbility(want, this.options);
        console.log("[MediaScannerSubscriber] connectServiceExtAbility result:" + this.connection);
    }

    disconnectServiceExtAbility(callback) {
        console.log("[MediaScannerSubscriber] disconnectServiceExtAbility");
        this.context.disconnectAbility(this.connection).then((data) => {
            console.log("[MediaScannerSubscriber] disconnectAbility success: " + data);
            callback(SUCCESS_CODE);
        }).catch((error) => {
            console.log('[MediaScannerSubscriber] disconnectAbility failed: ' + error);
            callback(ERROR_CODE);
        })
    }
}

function ScannerCallback(status: number, uri: string)
{
    console.log('[MediaScannerSubscriber] Scan Message callback');
    return 0;
}

let instance = undefined;
class MediaScannerSubscriber extends StaticSubscriberExtensionAbility {
    onReceiveEvent(event) {
        console.log('[MediaScannerSubscriber] onReceiveEvent, event:' + event.event);
        if (instance == undefined) {
            instance = mediaLibrary.getScannerInstance(this.context);
        }
        try {
            console.log('[MediaScannerSubscriber] start');
            instance.scanDir(event.event, ScannerCallback);
        } catch (error) {
            instance = undefined;
            console.log('[MediaScannerSubscriber] scan error:' + error);
        }
        console.log('[MediaScannerSubscriber] end');
    }
}

export default MediaScannerSubscriber
