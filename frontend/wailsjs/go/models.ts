export namespace config {
	
	export class Settings {
	    theme: string;
	    defaultEncryption: string;
	    deleteOriginal: boolean;
	    lastUsedLevel: string;
	    lastUsedChannel: number;
	
	    static createFrom(source: any = {}) {
	        return new Settings(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.theme = source["theme"];
	        this.defaultEncryption = source["defaultEncryption"];
	        this.deleteOriginal = source["deleteOriginal"];
	        this.lastUsedLevel = source["lastUsedLevel"];
	        this.lastUsedChannel = source["lastUsedChannel"];
	    }
	}

}

export namespace main {
	
	export class FileMetadata {
	    hint: string;
	    encryptionLevel: string;
	    channel: number;
	    method: string;
	    originalExt: string;
	
	    static createFrom(source: any = {}) {
	        return new FileMetadata(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.hint = source["hint"];
	        this.encryptionLevel = source["encryptionLevel"];
	        this.channel = source["channel"];
	        this.method = source["method"];
	        this.originalExt = source["originalExt"];
	    }
	}

}

