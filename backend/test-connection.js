const mongoose = require('mongoose');

const testConnection = async () => {
  try {
    // ทดสอบกับ Connection String ต่างๆ
    const testUris = [
      'mongodb+srv://connect_db_PRJCH:prjch64@chatchat-clusterdata.cbb4cyf.mongodb.net/connect_app?retryWrites=true&w=majority',
      'mongodb+srv://connect_db_PRJCH:prjch64@chatchat-clusterdata.cbb4cyf.mongodb.net/?retryWrites=true&w=majority',
      'mongodb+srv://connect_db_PRJCH:prjch64@chatchat-clusterdata.cbb4cyf.mongodb.net/test?retryWrites=true&w=majority'
    ];

    for (let i = 0; i < testUris.length; i++) {
      const uri = testUris[i];
      console.log(`\n🔗 Testing connection ${i + 1}/3...`);
      console.log('URI:', uri.replace(/:[^:]*@/, ':****@'));
      
      try {
        await mongoose.connect(uri, {
          useNewUrlParser: true,
          useUnifiedTopology: true,
          serverSelectionTimeoutMS: 5000
        });
        
        console.log('✅ Connection SUCCESSFUL!');
        
        // ทดสอบดู collections
        const db = mongoose.connection.db;
        const collections = await db.listCollections().toArray();
        console.log('📊 Collections found:', collections.map(c => c.name));
        
        await mongoose.disconnect();
        process.exit(0);
        
      } catch (error) {
        console.log('❌ Connection failed:', error.message);
        await mongoose.disconnect();
        
        // ลอง connection ต่อไป
        if (i < testUris.length - 1) {
          console.log('🔄 Trying next connection string...');
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      }
    }
    
    console.log('\n💡 All connection attempts failed.');
    console.log('Please check:');
    console.log('1. MongoDB Atlas IP whitelist');
    console.log('2. Database user credentials');
    console.log('3. Cluster status');
    process.exit(1);
    
  } catch (error) {
    console.error('Unexpected error:', error);
    process.exit(1);
  }
};

testConnection();