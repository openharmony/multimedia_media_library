import ServiceExtension from '@ohos.application.ServiceExtension'
import rpc from '@ohos.rpc'
import mediaLibrary from '@ohos.multimedia.mediaLibrary'

class StubTest extends rpc.RemoteObject{
    constructor(des) {
        if (typeof des === 'string') {
            super(des);
        } else {
            return null;
        }
    }

    queryLocalInterface(descriptor){
        return null;
    }

    getInterfaceDescriptor(){
        return "";
    };

    sendRequest(code, data, reply, options){
        return null;
    };

    getCallingPid(){
        return 0;
    };

    getCallingUid(){
        return 0;
    };

    attachLocalInterface(localInterface, descriptor){

    };

    //创建相关的实现
    onRemoteRequest(code, data, reply, option) {
        console.log("[ttt] [DataShareTest] onRemoteRequest 1");
        if (code === 1) {
            console.log("[ttt] [DataShareTest] code 1 begin");
            let op1 = data.readInt();
            let op2 = data.readInt();
            console.log("[ttt] [DataShareTest] op1 = " + op1 + ", op2 = " + op2);
            reply.writeInt(op1 + op2);
        } else {
            console.log("[ttt] [DataShareTest] onRemoteRequest code:" + code);
        }
        return true;
    }
}

class MediaDataService extends ServiceExtension{
    onCreate(want) {
        console.log('[ttt] [DataShareTest] ServiceExtAbility onCreate, want:' + want.abilityName);
    }

    onRequest(want, startId) {
        console.log('[ttt] [DataShareTest] ServiceExtAbility onRequest, want:' + want.abilityName + ', startId:' + startId);
    }

    onConnect(want) {
        console.log('[ttt] [DataShareTest] ServiceExtAbility onConnect , want:' + want.abilityName);
       // return new StubTest("test");
      return mediaLibrary.getMediaLibrary().getMediaRemoteStub(this.context);
    }

    onDisconnect(want) {
        console.log('[ttt] [DataShareTest] ServiceExtAbility onDisconnect , want:' + want.abilityName);
    }

    onDestroy() {console.log('[ttt] [DataShareTest] ServiceExtAbility onDestroy');}
}

export default MediaDataService