const mongoose = require('mongoose');

const testConnection = async () => {
  try {
    const uri = 'mongodb+srv://connect_db_PRJCH:prjch04@chatchat-clusterdata.cbb4cyf.mongodb.net/connect_app?retryWrites=true&w=majority';
    
    console.log('🔗 Testing connection with correct password...');
    console.log('URI:', uri.replace(/:[^:]*@/, ':****@'));
    
    await mongoose.connect(uri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 10000
    });
    
    console.log('✅ Connection SUCCESSFUL with password: prjch04!');
    
    // ทดสอบดู collections
    const db = mongoose.connection.db;
    const collections = await db.listCollections().toArray();
    console.log('📊 Collections found:', collections.map(c => c.name));
    
    // สร้าง collection ทดสอบ
    const testCollection = mongoose.connection.collection('test_connection');
    await testCollection.insertOne({ 
      message: 'Test connection successful', 
      timestamp: new Date() 
    });
    console.log('✅ Test data inserted successfully');
    
    process.exit(0);
    
  } catch (error) {
    console.error('❌ Connection failed:', error.message);
    
    if (error.message.includes('Authentication failed')) {
      console.log('💡 Authentication failed - please check:');
      console.log('   1. Username: connect_db_PRJCH');
      console.log('   2. Password: prjch04');
      console.log('   3. IP whitelist in MongoDB Atlas');
    }
    
    process.exit(1);
  }
};

testConnection();